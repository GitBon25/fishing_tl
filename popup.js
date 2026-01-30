const statusTitle = document.getElementById('status-title');
const domainName = document.getElementById('domain-name');
const detailsBox = document.getElementById('details-box');
const mainButton = document.getElementById('main-button');
const eduTip = document.getElementById('edu-tip');
const connectionStatus = document.getElementById('connection-status');

document.addEventListener('DOMContentLoaded', async function() {
    let currentTab;
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        currentTab = tabs[0];
        
        if (!currentTab.url) {
            showError("Не удалось получить URL текущей страницы");
            return;
        }
    } catch (error) {
        showError("Ошибка доступа к вкладке: " + error.message);
        return;
    }
    
    const url = new URL(currentTab.url);
    if (!url.protocol.startsWith('http')) {
        showError("Расширение работает только на веб-сайтах");
        return;
    }

    domainName.textContent = url.hostname;
    
    try {
        showLoading();
        
        const htmlContent = await getPageHtml(currentTab.id);

        const response = await fetch('http://10.0.1.14:5000/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: currentTab.url,
                html: htmlContent
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        updateUI(data);
        
        connectionStatus.classList.add('online');
        connectionStatus.title = "API подключен";
        
    } catch (error) {
        console.error('Ошибка при анализе сайта:', error);
        showError("Ошибка при проверке сайта: " + error.message);
        connectionStatus.classList.remove('online');
        connectionStatus.title = "Нет соединения с API";
    }
});

async function getPageHtml(tabId) {
    return new Promise((resolve, reject) => {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            function: () => document.documentElement.outerHTML
        }, (results) => {
            if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
            } else if (results && results[0]) {
                resolve(results[0].result);
            } else {
                reject(new Error("Не удалось получить HTML страницы"));
            }
        });
    });
}

function updateUI(data) {
    const body = document.body;
    
    body.className = 'state-' + data.state;
    
    statusTitle.textContent = data.statusTitle;
    
    if (data.domain) {
        document.getElementById('domain-name').textContent = data.domain;
    }
    
    if (data.text) {
        eduTip.textContent = data.text;
    }
    
    updateReasons(data.reasons);
    
    setupActionButton(data.state, data.score);
}

function updateReasons(reasons) {
    const detailsBox = document.getElementById('details-box');
    detailsBox.innerHTML = '';
    
    if (!reasons || reasons.length === 0) {
        detailsBox.style.display = 'none';
        return;
    }
    
    reasons.forEach((reason, index) => {
        const row = document.createElement('div');
        row.className = 'detail-row';
        
        const icon = document.createElement('span');
        icon.className = 'icon';
        icon.textContent = reason.icon;
        
        const textSpan = document.createElement('span');
        
        textSpan.textContent = reason.text;
        
        row.appendChild(icon);
        row.appendChild(textSpan);
        detailsBox.appendChild(row);
    });
    
    detailsBox.style.display = 'block';
}

function setupActionButton(state, score) {
    const mainButton = document.getElementById('main-button');
    
    if (state === 'danger') {
        mainButton.style.display = 'block';
        mainButton.textContent = 'Покинуть сайт';
        mainButton.onclick = function() {
            chrome.tabs.update({ url: 'chrome://newtab' });
        };
    } else if (state === 'warning') {
        mainButton.style.display = 'block';
        mainButton.textContent = 'Будьте осторожны';
        mainButton.onclick = function() {
            alert('Этот сайт выглядит подозрительно. Будьте осторожны при вводе личных данных.');
        };
    } else {
        mainButton.style.display = 'none';
    }
}

function showLoading() {
    const body = document.body;
    body.className = 'state-warning';
    
    statusTitle.textContent = 'ПРОВЕРКА...';
    document.getElementById('domain-name').textContent = 'Анализ безопасности...';
    eduTip.textContent = 'Идет проверка сайта на фишинг...';
    
    const detailsBox = document.getElementById('details-box');
    detailsBox.innerHTML = '<div class="detail-row">Загрузка данных...</div>';
    detailsBox.style.display = 'block';
    
    document.getElementById('main-button').style.display = 'none';
}

function showError(message) {
    const body = document.body;
    body.className = 'state-warning';
    
    statusTitle.textContent = 'ОШИБКА';
    eduTip.textContent = message;
    
    const detailsBox = document.getElementById('details-box');
    detailsBox.innerHTML = '<div class="detail-row">Не удалось проверить сайт. Проверьте соединение.</div>';
    detailsBox.style.display = 'block';
    
    document.getElementById('main-button').style.display = 'none';
}