import re
import ipaddress
import Levenshtein
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)


class Domain(db.Model):
    __tablename__ = 'domains'

    id = db.Column(db.Integer, primary_key=True)
    rank = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), unique=True, nullable=False)

    def __repr__(self):
        return f'<Domain {self.domain}>'


class BKTree:
    def __init__(self):
        self.tree = None

    def add(self, word):
        if self.tree is None:
            self.tree = (word, {})
            return
        node = self.tree
        while True:
            parent_word, children = node
            distance = Levenshtein.distance(word, parent_word)
            if distance == 0:
                return
            if distance in children:
                node = children[distance]
            else:
                children[distance] = (word, {})
                break

    def search(self, query, max_dist):
        if self.tree is None:
            return []
        candidates = [self.tree]
        results = []
        while candidates:
            node_word, children = candidates.pop()
            distance = Levenshtein.distance(query, node_word)
            if distance <= max_dist:
                results.append((distance, node_word))
            low, high = distance - max_dist, distance + max_dist
            for d, child in children.items():
                if low <= d <= high:
                    candidates.append(child)
        return results


bk_tree = BKTree()

EXACT_WHITELIST = set()
SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.win', '.online', '.info', '.gq', '.tk', '.ml', '.ga', '.cf', '.cn'}


def init_and_load_db():
    with app.app_context():
        db.create_all()

        domains = Domain.query.all()

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
        if not url:
            return ""
        url = url.strip().lower()
        url = re.sub(r'^https?://', '', url)
        url = re.sub(r'^www\.', '', url)
        parts = re.split(r'[/?:@]', url)
        if parts:
            return parts[0]
        return url
    except:
        return ""


def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def analyze_url_structure(full_url, domain: str):
    score = 0
    reasons = []

    if not full_url.startswith('https'):
        score += 100
        reasons.append(["🔓", "Использование протокола HTTP"])

    if is_ip_address(domain):
        score += 80
        reasons.append(["📛", "Использование IP-адреса вместо домена"])
        return score, reasons

    if '@' in full_url:
        score += 60
        reasons.append(["🎣", "Обнаружен символ '@' (попытка обмана URL)"])

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 15
            reasons.append(["🚩", f"Подозрительная доменная зона: {tld}"])
            break

    if domain.count('.') > 3:
        score += 20
        reasons.append(["🔗", "Подозрительно много поддоменов (4+)"])

    return score, reasons


def analyze_typosquatting(current_domain):
    normalized = normalize_homoglyphs(current_domain)

    if normalized in EXACT_WHITELIST:
        if current_domain != normalized:
            return 100, ["🔤", f"Homoglyph attack! Подмена символов под {normalized}"]
        return 0, None

    for legit in EXACT_WHITELIST:
        if normalized.endswith('.' + legit):
            return 0, None

    max_distance = 2
    found = bk_tree.search(normalized, max_distance)

    if found:
        found.sort(key=lambda x: x[0])
        best_dist, best_match = found[0]
        risk = 90 if best_dist == 1 else 70
        return risk, ["⚠️", f"Typosquatting: {best_match} (dist: {best_dist})"]

    return 0, None


def analyze_content_optimized(html_raw):
    score = 0
    reasons = []

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
            score += 70
            reasons.append(["🚨", "Ввод пароля + Срочность/Деньги"])
        else:
            score += 10
            reasons.append(["🔑", "Форма ввода пароля"])
    else:
        if found_money and found_urgency:
            score += 40
            reasons.append(["📢", "Текст содержит угрозы и финансовые требования (Скам)"])

    return score, reasons


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json

        full_url = data.get('url', '')
        html = data['html']

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

        if html:
            cont_score, cont_reasons = analyze_content_optimized(html)

            if (ts_score > 0 or url_score >= 50) and cont_score > 0:
                total_score = 100
            else:
                total_score += cont_score
            all_reasons.extend(cont_reasons)

        all_reasons = [{"icon": i[0], "text": i[1]} for i in all_reasons]

        final_score = min(total_score, 100)

        if final_score >= 70:
            statusTitle = "ОБНАРУЖЕНА УГРОЗА"
            state = "danger"
            text = "Это фишинговый сайт! Не вводите здесь пароли и данные карт."
        elif final_score >= 30:
            statusTitle = "ПОДОЗРИТЕЛЬНЫЙ САЙТ"
            state = "warning"
            text = "Сайт выглядит странно. Внимательно проверьте адресную строку."
        else:
            statusTitle = "САЙТ БЕЗОПАСЕН"
            state = "safe"
            text = "Угроз не обнаружено, но всегда проверяйте адрес перед вводом пароля."

        data = {
            "score": final_score,
            "reasons": all_reasons,
            "domain": domain,
            "statusTitle": statusTitle,
            "text": text,
            "state": state
        }

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':

    app.run(host='0.0.0.0', debug=False, port=80)
