import csv
import os
from flask import Flask, request, jsonify
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from collections import defaultdict

app = Flask(__name__)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
# Словарь, где ключ - длина домена, значение - список доменов этой длины
# Пример: { 6: ['vk.com'], 10: ['google.com', 'yandex.ru'] }
DOMAINS_BY_LENGTH = defaultdict(list)
# Обычный список для точного поиска
EXACT_WHITELIST = set()

def load_whitelist_optimized(filename='whitelist.csv'):
    """
    Загружает белый список и строит индекс по длине строк.
    Это позволяет избежать перебора всей базы.
    """
    try:
        if not os.path.exists(filename):
            print(f"File {filename} not found.")
            return

        with open(filename, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader, None) # Skip header
            count = 0
            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip().lower()
                    # 1. Сохраняем для быстрого точного поиска O(1)
                    EXACT_WHITELIST.add(domain)
                    # 2. Индексируем по длине для Левенштейна
                    DOMAINS_BY_LENGTH[len(domain)].append(domain)
                    count += 1
        print(f"Whitelist loaded: {count} domains. Indexed by length.")
    except Exception as e:
        print(f"Error loading whitelist: {e}")

# Загружаем при старте
load_whitelist_optimized()

# Классический Левенштейн (можно ускорить, используя библиотеку python-Levenshtein или rapidfuzz)
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def clean_domain(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        domain = domain.split(':')[0]
        return domain.lower()
    except:
        return ""

def analyze_typosquatting(current_domain):
    """
    Оптимизированная проверка на похожесть.
    Сложность снижена с O(N) до O(N / K), где K - разброс длин доменов.
    """
    # 1. Точное совпадение - мгновенный выход (безопасно)
    if current_domain in EXACT_WHITELIST:
        return 0, None
    
    # Проверяем поддомены официальных сайтов (mail.google.com)
    for legit in EXACT_WHITELIST:
        if current_domain.endswith('.' + legit):
            return 0, None

    input_len = len(current_domain)
    max_distance = 2 # Максимально допустимое отличие
    
    # Мы проверяем только те домены из базы, длина которых отличается 
    # не более чем на max_distance.
    # Если входной домен 10 символов, смотрим корзины: 8, 9, 10, 11, 12.
    candidates = []
    for length in range(input_len - max_distance, input_len + max_distance + 1):
        if length in DOMAINS_BY_LENGTH:
            candidates.extend(DOMAINS_BY_LENGTH[length])
    
    # Теперь применяем "тяжелый" Левенштейн только к кандидатам
    for legit_domain in candidates:
        dist = levenshtein_distance(current_domain, legit_domain)
        if 0 < dist <= max_distance:
            return 85, f"Typosquatting detected! Similar to official domain: {legit_domain} (Distance: {dist})"
            
    return 0, None

def analyze_content(soup):
    """
    Умный анализ контента: ищем сочетание 'Опасные слова' + 'Форма ввода пароля'.
    """
    score = 0
    reasons = []
    
    # Получаем весь текст
    text_content = soup.get_text(" ", strip=True).lower()
    
    # 1. Поиск формы ввода пароля (Критический маркер)
    has_password_field = bool(soup.find('input', {'type': 'password'}))
    
    # 2. Группы ключевых слов
    # Слова, требующие действия
    action_keywords = ['verify', 'confirm', 'update', 'reactivate', 'подтвердить', 'обновить', 'восстановить']
    # Слова, нагнетающие срочность или угрозу
    urgency_keywords = ['suspended', 'locked', 'urgent', 'immediately', '24 hours', 'заблокирован', 'срочно', 'удаление']
    # Финансовые маркеры
    financial_keywords = ['card', 'bank', 'payment', 'billing', 'карта', 'платеж', 'реквизиты']

    # Логика подсчета
    found_action = any(k in text_content for k in action_keywords)
    found_urgency = any(k in text_content for k in urgency_keywords)
    found_financial = any(k in text_content for k in financial_keywords)

    # Сценарий A: Есть поле пароля + слова действия/срочности (Высокий риск фишинга учетных данных)
    if has_password_field:
        if found_action or found_urgency:
            score += 65
            reasons.append("Обнаружена форма ввода пароля вместе с требованием действий/угрозами.")
        elif found_financial:
             score += 75
             reasons.append("Форма пароля на странице с финансовой тематикой.")
        else:
             score += 30 # Просто форма пароля на неизвестном домене - подозрительно, но бывает
             reasons.append("Найден ввод пароля на недоверенном домене.")

    # Сценарий B: Нет пароля, но есть текст (Социальная инженерия / скам)
    else:
        if found_action and found_urgency and found_financial:
            score += 40
            reasons.append("Текст содержит признаки финансового мошенничества (срочность + деньги).")
        elif found_urgency and found_action:
            score += 25
            reasons.append("Текст пытается вызвать панику или заставить выполнить действие.")

    return score, reasons

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        domain_raw = data.get('domain', '')
        html = data.get('html', '')

        # 1. Очистка
        current_domain = clean_domain(domain_raw)
        if not current_domain:
            return jsonify({"error": "Invalid domain"}), 400

        total_score = 0
        all_reasons = []

        # 2. Проверка домена (Быстрая)
        ts_score, ts_reason = analyze_typosquatting(current_domain)
        if ts_score > 0:
            total_score += ts_score
            all_reasons.append(ts_reason)

        # 3. Анализ контента (только если HTML передан)
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            cont_score, cont_reasons = analyze_content(soup)
            
            # Если домен похож на официальный, контентный анализ удваивает вес,
            # так как это подтверждает атаку.
            if ts_score > 0 and cont_score > 0:
                total_score = 100 # Бинго, это точно фишинг
            else:
                total_score += cont_score
            
            all_reasons.extend(cont_reasons)

        total_score = min(total_score, 100)

        return jsonify({
            "domain": current_domain,
            "risk_score": total_score,
            "reasons": all_reasons,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)