let TRUSTED_DOMAINS = []; // берется из whitelist.csv
const TARGET_BRANDS = ["sber", "vk", "gosuslugi", "google", "yandex"]; // Ключевые слова для поиска

// Алгоритм Левенштейна (сравнение строк)
function getLevenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
            }
        }
    }
    return matrix[b.length][a.length];
}

//Белый список
function checkWhitelist(domain) {
    if (TRUSTED_DOMAINS.includes(domain)) {
        return { isSafe: true, score: 0, reason: "Trusted Source" };
    }
    return { isSafe: false, score: 0, reason: null };
}

//Анатомия URL (Синтаксис)
function checkUrlSyntax(urlObj, domain) {
    let score = 0;
    let reasons = [];

    // Проверка на IP-адрес
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        score += 50;
        reasons.push("Используется IP вместо домена");
    }

    // Проверка на символ @ (атака на userinfo)
    if (urlObj.username || urlObj.password || urlObj.href.includes('@')) {
        score += 40;
        reasons.push("Подозрительный символ @ в адресе");
    }

    // Проверка на длину и количество поддоменов (login.secure.bank.verify.com)
    if (domain.split('.').length > 4) {
        score += 20;
        reasons.push("Слишком много поддоменов");
    }

    // Проверка доменной зоны
    if (domain.endsWith('.xyz') || domain.endsWith('.tk') || domain.endsWith('.top')) {
        score += 15;
        reasons.push("Подозрительная доменная зона");
    }

    return { score, reasons };
}

//Бренд-имперсонация (Левенштейн)
function checkImpersonation(domain) {
    let score = 0;
    let reasons = [];
    
    const domainBody = domain.split('.')[0];

    for (let brand of TRUSTED_DOMAINS) {
        let trustedName = brand.split('.')[0];
        if (trustedName.length < 4) continue;

        //Расстояние Левенштейна (опечатки)
        let dist = getLevenshteinDistance(domainBody, trustedName);
        
        //Если отличие всего в 1 символ (sberbank vs sberbanlk)
        if (dist === 1) {
            score += 80;
            reasons.push(`Попытка имитации бренда ${trustedName} (Тайпосквоттинг)`);
            break; // Нашли угрозу - выходим
        }

        //Вхождение слова (sberbank-bonus.ru)
        if (domain.includes(trustedName) && domain !== brand) {
            score += 60;
            reasons.push(`Имя бренда ${trustedName} в постороннем домене`);
            break;
        }
    }

    return { score, reasons };
}


async function performSecurityCheck(tabId, urlString) {
    try {
        const url = new URL(urlString);
        const domain = url.hostname.replace(/^www\./, '').toLowerCase();

        //Проверка вайтлиста
        const whitelistCheck = checkWhitelist(domain);
        if (whitelistCheck.isSafe) {
            updateIcon("SAFE", tabId);
            return;
        }

        // Инициализируем общий счетчик риска
        let totalScore = 0;
        let report = [];

        //Проверка синтаксиса
        const syntaxCheck = checkUrlSyntax(url, domain);
        totalScore += syntaxCheck.score;
        report.push(...syntaxCheck.reasons);

        //Проверка бренда
        const impersonationCheck = checkImpersonation(domain);
        totalScore += impersonationCheck.score;
        report.push(...impersonationCheck.reasons);

        //контекстный анализ (DOM)
        //Запускаем скрипт на странице, чтобы проверить поля пароля и заголовок
        //Это асинхронная операция
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            function: analyzePageContentDOM
        }, (results) => {
            if (results && results[0] && results[0].result) {
                const domResult = results[0].result;
                
                //Добавляем баллы от анализа контента
                if (domResult.hasPasswordInput) {
                    //Если сайт неизвестный, но просит пароль - это риск
                    totalScore += 20; 
                    report.push("Запрос пароля на непроверенном сайте");
                }
                
                //Финальное принятие решения
                finalizeVerdict(tabId, totalScore, report);
            }
        });

    } catch (e) {
        console.error("Ошибка проверки:", e);
    }
}

//Эта функция будет внедрена и выполнена на странице пользователя
function analyzePageContentDOM() {
    return {
        hasPasswordInput: !!document.querySelector('input[type="password"]'),
        pageTitle: document.title,
    };
}


function finalizeVerdict(tabId, score, report) {
    console.log(`URL Analysis Score: ${score}`, report);

    if (score >= 50) {
        //красный уровень
        updateIcon("DANGER", tabId);
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: (reasons) => {
                alert(`⚠️ КИБЕРУГРОЗА ОБНАРУЖЕНА!\n\nПричины:\n- ${reasons.join('\n- ')}\n\nРекомендуем закрыть эту вкладку.`);
                document.body.style.border = "10px solid red";
            },
            args: [report]
        });
    } else if (score >= 20) {
        //желтый уровень
        updateIcon("WARNING", tabId);
    } else {
        //нейтральный
        updateIcon("UNKNOWN", tabId);
    }
}

function updateIcon(status, tabId) {
    let color = "gray";
    let text = "?";
    if (status === "SAFE") { color = "green"; text = "OK"; }
    if (status === "DANGER") { color = "red"; text = "!!!"; }
    if (status === "WARNING") { color = "orange"; text = "!"; }
    
    chrome.action.setBadgeText({ text: text, tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

// Слушатель событий
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        performSecurityCheck(tabId, tab.url);
    }
});