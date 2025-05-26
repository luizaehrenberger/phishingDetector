from flask import Flask, render_template, request, send_file
from utils.whois_check import get_domain_age
from utils.ssl_check import get_ssl_info
import requests
import csv
import io
import Levenshtein

app = Flask(__name__)
historico = []

import tldextract

def is_phishing_url(url):
    try:
        feed_url = "https://openphish.com/feed.txt"
        response = requests.get(feed_url, timeout=10)
        phishing_urls = response.text.splitlines()

        ext_input = tldextract.extract(url)
        input_root = f"{ext_input.domain}.{ext_input.suffix}".lower()

        for phishing_url in phishing_urls:
            ext_phish = tldextract.extract(phishing_url)
            phish_root = f"{ext_phish.domain}.{ext_phish.suffix}".lower()
            if input_root == phish_root:
                return True
        return False
    except Exception as e:
        print("Erro ao verificar OpenPhish:", e)
        return False


def check_levenshtein(domain):
    conhecidos = ['google.com', 'facebook.com', 'apple.com', 'insper.edu.br', 'hotmail.com']
    for conhecido in conhecidos:
        dist = Levenshtein.distance(domain, conhecido)
        if dist <= 3:  # tolerância ajustável
            return f"🚩 Muito parecido com: {conhecido}"
    return "OK"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        domain = url.split('/')[2] if '://' in url else url.split('/')[0]

        age = get_domain_age(domain)
        ssl_info = get_ssl_info(domain)
        phishing = is_phishing_url(url)
        similar = check_levenshtein(domain)

        result = {
            'url': url,
            'domain': domain,
            'age': age,
            'ssl': ssl_info,
            'phishing': phishing,
            'similar': similar
        }

        historico.append(result)

    return render_template('index.html', result=result, historico=historico)

@app.route('/exportar')
def exportar_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['URL', 'Domínio', 'Idade (dias)', 'SSL', 'Phishing', 'Similaridade'])

    for r in historico:
        writer.writerow([r['url'], r['domain'], r['age'], r['ssl'], 'Sim' if r['phishing'] else 'Não', r['similar']])

    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='historico.csv')

if __name__ == '__main__':
    app.run(debug=True)