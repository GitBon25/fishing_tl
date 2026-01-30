from flask import Flask, request, jsonify
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

# 1. СПИСОК ЗАЩИЩАЕМЫХ БРЕНДОВ (Whitelisting)
# В реальности этот список должен быть в базе данных.
# Формат: 'бренд': 'официальный_домен'
TARGET_DOMAINS = {
    'google': 'google.com',
    'facebook': 'facebook.com',
    'vk': 'vk.com',
    'sberbank': 'sberbank.ru',
    'instagram': 'instagram.com',
    'twitter': 'twitter.com',
    'yandex': 'yandex.ru'
}

# Алгоритм Левенштейна (расстояние редактирования)
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

# Функция очистки домена от http/https/www
def clean_domain(url):
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower()
    except:
        return ""

def analyze_security(domain_raw, html_content, meta_tags):
    score = 0
    reasons = []
    
    current_domain = clean_domain(domain_raw)
    
    # --- ЭТАП 1: Проверка на Тайпосквоттинг (Левенштейн) ---
    # Пытаемся понять, не косит ли домен под популярный бренд
    for brand, legit_domain in TARGET_DOMAINS.items():
        # Если это официальный домен - сразу выход, все ок
        if current_domain == legit_domain or current_domain.endswith('.' + legit_domain):
            return 0, ["Официальный верифицированный домен"]

        # Считаем разницу
        dist = levenshtein_distance(current_domain, legit_domain)
        
        # Если разница очень мала (1-2 символа), но это НЕ официальный домен
        # Пример: go0gle.com vs google.com (дистанция 1)
        if 0 < dist <= 2:
            score += 80
            reasons.append(f"Высокая вероятность подмены домена {legit_domain} (Тайпосквоттинг)")
            break # Достаточно одного совпадения

    # --- ЭТАП 2: Анализ HTML контента ---
    # soup = BeautifulSoup(html_content, 'html.parser')
    # text_content = soup.get_text().lower()

    # # Поиск полей ввода пароля
    # password_inputs = soup.find_all('input', {'type': 'password'})
    # has_password_field = len(password_inputs) > 0
    
    # if has_password_field:
    #     # Если есть поле пароля на неизвестном домене - это уже подозрительно
    #     # Но само по себе не преступление, поэтому добавляем немного очков
    #     if score == 0: # Если еще не помечен как фишинг
    #         score += 10
    #         reasons.append("На сайте есть ввод пароля")

    # --- ЭТАП 3: Анализ форм (Action Hijacking) ---
    # forms = soup.find_all('form')
    # for form in forms:
    #     action = form.get('action')
    #     if action:
    #         # Если форма отправляет данные на полный URL (http...)
    #         if action.startswith('http'):
    #             action_domain = clean_domain(action)
    #             # Если домен отправки не совпадает с текущим доменом
    #             if action_domain and action_domain != current_domain:
    #                 # И это не поддомен и не OAuth (как google auth)
    #                 if not action_domain.endswith(current_domain):
    #                     score += 50
    #                     reasons.append(f"Форма отправляет данные на сторонний домен: {action_domain}")

    # --- ЭТАП 4: Подозрительные слова в Meta и Title ---
    suspicious_keywords = ['verify', 'account suspended', 'confirm identity', 'подтвердите аккаунт', 'блокировка', 'update payment']
    
    combined_meta = (str(meta_tags) + soup.title.string if soup.title else "").lower()
    
    for kw in suspicious_keywords:
        if kw in combined_meta or kw in text_content[:500]: # Проверяем начало текста
            score += 20
            reasons.append(f"Найдены подозрительные ключевые слова: {kw}")

    # Нормализация оценки (не больше 100)
    score = min(score, 100)
    
    return score, reasons

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data"}), 400

        domain = data.get('domain', '')
        html = data.get('html', '')
        meta = data.get('meta', {}) # Ожидаем словарь или строку

        score, reasons = analyze_security(domain, html, meta)

        # Формируем вердикт
        status = "safe"
        if score >= 70:
            status = "DANGER"
        elif score >= 30:
            status = "WARNING"

        return jsonify({
            "domain": domain,
            # "status": status,
            "risk_score": score, # 0 - 100
            "reasons": reasons
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # debug=True для разработки, host='0.0.0.0' чтобы слушать внешние запросы
    app.run(debug=True, port=5000)