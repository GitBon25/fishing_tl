import os
import re
import ipaddress
import Levenshtein
import random
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///whitelist.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

db = SQLAlchemy(app)

SECURITY_TIPS = [
    "Никогда не вводите пароли, если адрес сайта кажется вам подозрительным.",
    "Наличие значка 'замка' (HTTPS) не гарантирует, что сайт безопасен. Мошенники тоже его используют.",
    "Используйте менеджер паролей: он не подставит ваши данные на поддельный сайт.",
    "Включите двухфакторную аутентификацию (2FA) на всех важных аккаунтах.",
    "Банки никогда не просят CVV-код или код из SMS для 'отмены операции'.",
    "Проверяйте адрес отправителя в письмах, прежде чем переходить по ссылкам.",
    "Мошенники часто используют срочность ('Ваш аккаунт удалят!'), чтобы вызвать панику.",
    "Регулярно обновляйте браузер и антивирус для защиты от новых угроз.",
    "Не скачивайте файлы с сайтов, в надежности которых вы не уверены.",
    "Если сайт выглядит как копия известного бренда, но адрес другой — это фишинг.",
    "Используйте сложные и разные пароли для разных сервисов.",
    "Не переходите по коротким ссылкам (bit.ly и др.) от незнакомых людей.",
    "Если предложение в интернете звучит слишком хорошо, чтобы быть правдой — это обман.",
    "Проверяйте отзывы о магазине в интернете перед покупкой.",
    "Не вводите личные данные при подключении к открытому Wi-Fi в кафе.",
    "Наведите курсор на ссылку в письме, чтобы увидеть реальный адрес, куда она ведет.",
    "Сохраняйте важные сайты в закладки, чтобы не искать их каждый раз в поиске."
]

class WhitelistDomain(db.Model):
    __tablename__ = 'whitelist'
    id = db.Column(db.Integer, primary_key=True)
    rank = db.Column(db.Integer, nullable=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    def __repr__(self): return f'<Domain {self.domain}>'

class BKTree:
    def __init__(self): self.tree = None
    def add(self, word):
        if self.tree is None: self.tree = (word, {}); return
        node = self.tree
        while True:
            parent_word, children = node
            distance = Levenshtein.distance(word, parent_word)
            if distance == 0: return
            if distance in children: node = children[distance]
            else: children[distance] = (word, {}); break
    def search(self, query, max_dist):
        if self.tree is None: return []
        candidates = [self.tree]; results = []
        while candidates:
            node_word, children = candidates.pop()
            distance = Levenshtein.distance(query, node_word)
            if distance <= max_dist: results.append((distance, node_word))
            low, high = distance - max_dist, distance + max_dist
            for d, child in children.items():
                if low <= d <= high: candidates.append(child)
        return results

bk_tree = BKTree()
EXACT_WHITELIST = set()
SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.win', '.online', '.info', '.gq', '.tk', '.ml', '.ga', '.cf', '.cn'}

def init_and_load_db():
    with app.app_context():
        db.create_all()
        
        domains = WhitelistDomain.query.all()
        for row in domains:
            d = row.domain.strip().lower()
            EXACT_WHITELIST.add(d)
            bk_tree.add(d)

init_and_load_db()

def normalize_homoglyphs(text):
    mapping = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'к': 'k', 'м': 'm',
        'А': 'A', 'С': 'C', 'Е': 'E', 'О': 'O', 'Р': 'P', 'Х': 'X', 'У': 'Y', 'К': 'K', 'М': 'M'
    }
    return "".join(mapping.get(char, char) for char in text)

def clean_domain(url):
    try:
        if not url: return ""
        url = url.strip().lower()
        url = re.sub(r'^https?://', '', url)
        url = re.sub(r'^www\.', '', url)
        parts = re.split(r'[/?:@]', url)
        if parts: return parts[0]
        return url
    except: return ""

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError: return False

def analyze_url_structure(full_url, domain):
    score = 0
    reasons = []

    if is_ip_address(domain):
        score += 90
        reasons.append(["📛", "Сайт использует IP-адреса вместо домена"])
        return score, reasons

    if '@' in full_url:
        score += 100
        reasons.append(["🎣", "Обнаружен символ '@' (скрытие реального адреса)"])

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(["🚩", f"Дешевая доменная зона: {tld}"])
            break

    if domain.count('.') > 3:
        score += 15
        reasons.append(["🔗", "Странная структура (много поддоменов)"])

    return score, reasons

def analyze_typosquatting(current_domain):
    normalized = normalize_homoglyphs(current_domain)

    if normalized in EXACT_WHITELIST:
        if current_domain != normalized:
            return 100, ["🔤", f"Подмена символов (Омоглифы) под {normalized}"]
        return 0, None 

    for legit in EXACT_WHITELIST:
        if normalized.endswith('.' + legit):
            return 0, None

    max_distance = 2
    found = bk_tree.search(normalized, max_distance)

    if found:
        found.sort(key=lambda x: x[0])
        best_dist, best_match = found[0]
        
        risk = 90 if best_dist == 1 else 60
        
        return risk, ["⚠️", f"Похоже на официальный сайт: {best_match}"]

    return 0, None

def analyze_content_optimized(html_raw):
    score = 0
    reasons = []
    has_pass = False

    if not html_raw:
        return 0, [], False

    if len(html_raw) > 500_000:
        html_raw = html_raw[:500_000]

    soup = BeautifulSoup(html_raw, 'html.parser')
    for tag in soup(["script", "style", "svg", "img", "iframe", "noscript", "video", "audio"]):
        tag.decompose()

    text = soup.get_text(" ", strip=True).lower()

    triggers = {
        'urgent': ['blocked', 'suspended', 'immediately', 'urgent', 'заблокирован', 'срок', 'срочно', '24 часа', 'внимание'],
        'money': ['card', 'cvv', 'bank', 'payment', 'карта', 'платеж', 'реквизиты', 'банк', 'средства'],
    }

    found_urgency = any(w in text for w in triggers['urgent'])
    found_money = any(w in text for w in triggers['money'])
    has_pass = bool(soup.find('input', {'type': 'password'}))

    if has_pass:
        if found_urgency or found_money:
            score += 80
            reasons.append(["🚨", "Ввод пароля + Угрозы/Финансы"])
        else:
            score += 35
            reasons.append(["🔑", "Запрос пароля на неизвестном сайте"])
    else:
        if found_money and found_urgency:
            score += 45
            reasons.append(["📢", "Подозрительный текст (Скам/Вымогательство)"])

    return score, reasons, has_pass

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        full_url = data.get('domain', '')
        html = data.get('html', '')

        domain = clean_domain(full_url)
        if not domain:
            return jsonify({"error": "Bad URL"}), 400

        total_score = 0
        all_reasons = []

        url_score, url_reasons = analyze_url_structure(full_url, domain)
        total_score += url_score
        all_reasons.extend(url_reasons)

        ts_score, ts_reason = analyze_typosquatting(domain)
        if ts_score > 0:
            total_score += ts_score
            all_reasons.append(ts_reason)

        has_password_field = False
        if html:
            cont_score, cont_reasons, has_pass = analyze_content_optimized(html)
            total_score += cont_score
            all_reasons.extend(cont_reasons)
            has_password_field = has_pass
        
        if ts_score > 0 and has_password_field:
            total_score = 100
            if not any("сбор паролей" in r[1] for r in all_reasons):
                all_reasons.insert(0, ["🔥", "КРИТИЧНО: Поддельный сайт собирает пароли!"])

        if ".xyz" in domain or ".top" in domain:
            if has_password_field:
                 total_score = max(total_score, 75)
        
        final_score = min(total_score, 100)

        if final_score >= 70:
            statusTitle = "ОБНАРУЖЕНА УГРОЗА"
            state = "danger"
        elif final_score >= 30:
            statusTitle = "ПОДОЗРИТЕЛЬНЫЙ САЙТ"
            state = "warning"
        else:
            statusTitle = "САЙТ БЕЗОПАСЕН"
            state = "safe"

        random_tip = random.choice(SECURITY_TIPS)

        return jsonify({
            "score": final_score,
            "reasons": all_reasons,
            "domain": domain,
            "statusTitle": statusTitle,
            "tip": random_tip,
            "state": state
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)