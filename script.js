

      'use strict';

      var THEME_STORAGE_KEY = 'checkprotect-theme';

      function getStoredTheme() {
        try {
          return localStorage.getItem(THEME_STORAGE_KEY);
        } catch (e) {
          return null;
        }
      }

      function storeTheme(theme) {
        try {
          localStorage.setItem(THEME_STORAGE_KEY, theme);
        } catch (e) {
          // Ignore storage errors
        }
      }

      function setTheme(theme) {
        var root = document.documentElement;
        if (theme !== 'dark') {
          theme = 'light';
        }
        root.setAttribute('data-theme', theme);
        updateThemeToggleLabel(theme);
      }

      function updateThemeToggleLabel(theme) {
        var toggleButton = document.getElementById('themeToggle');
        if (!toggleButton) {
          return;
        }

        var isDark = theme === 'dark';
        toggleButton.setAttribute('aria-pressed', isDark ? 'true' : 'false');
        toggleButton.setAttribute('aria-label', isDark ? 'Activer le mode clair' : 'Activer le mode sombre');
        toggleButton.setAttribute('title', isDark ? 'Activer le mode clair' : 'Activer le mode sombre');
      }

      function initThemeToggle() {
        var stored = getStoredTheme();
        var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

        if (stored === 'dark' || stored === 'light') {
          setTheme(stored);
        } else {
          updateThemeToggleLabel(prefersDark ? 'dark' : 'light');
        }

        var toggleButton = document.getElementById('themeToggle');
        if (!toggleButton) {
          return;
        }

        toggleButton.addEventListener('click', function () {
          var attrTheme = document.documentElement.getAttribute('data-theme');
          var current = attrTheme === 'dark' || attrTheme === 'light'
            ? attrTheme
            : ((window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light');
          var next = current === 'dark' ? 'light' : 'dark';
          setTheme(next);
          storeTheme(next);
        });
      }

      document.addEventListener('DOMContentLoaded', initThemeToggle);

      function clearAll() {
        document.getElementById('input').value = '';
        document.getElementById('output').hidden = true;
      }

      function extractUrls(text) {
        var matches = text.match(/https?:\/\/[^\s<>")]+/gi) || [];
        return Array.from(new Set(matches));
      }

      function getHostname(rawUrl) {
        try {
          var parsed = new URL(rawUrl);
          return parsed.hostname.toLowerCase().replace(/^www\./, '');
        } catch (e) {
          return '';
        }
      }

      function safeDecode(value) {
        try {
          return decodeURIComponent(value || '');
        } catch (e) {
          return String(value || '');
        }
      }

      function getRootDomain(hostname) {
        var clean = (hostname || '').toLowerCase().replace(/^www\./, '');
        var parts = clean.split('.').filter(Boolean);
        if (parts.length <= 2) {
          return clean;
        }
        return parts.slice(-2).join('.');
      }

      function isHighEntropyValue(value) {
        var normalized = String(value || '').replace(/[%\s._-]/g, '');
        if (normalized.length < 24) {
          return false;
        }
        if (/^[a-f0-9]{24,}$/i.test(normalized)) {
          return true;
        }
        if (/^[a-z0-9+/=]{30,}$/i.test(normalized) && /\d/.test(normalized) && /[a-z]/i.test(normalized)) {
          return true;
        }
        return false;
      }

      function isGeneratedSubdomain(hostname) {
        var host = String(hostname || '').toLowerCase();
        var firstLabel = host.split('.')[0] || '';
        if (firstLabel.length < 8) {
          return false;
        }
        var alphaNumOnly = /^[a-z0-9-]+$/.test(firstLabel);
        var hasDigit = /\d/.test(firstLabel);
        return alphaNumOnly && hasDigit;
      }

      async function queryPhishStatsByHost(hostname) {
        if (!hostname) {
          return [];
        }

        var proxyUrl = '/api/phishstats?host=' + encodeURIComponent(hostname);

        try {
          var proxyResponse = await fetch(proxyUrl, {
            method: 'GET',
            headers: { 'accept': 'application/json' }
          });

          if (proxyResponse.ok) {
            var proxyPayload = await proxyResponse.json();
            return Array.isArray(proxyPayload) ? proxyPayload : [];
          }
        } catch (proxyErr) {
          // fallback handled below
        }

        var endpoint = 'https://api.phishstats.info/api/phishing';
        var whereClause = '(url,like,' + hostname + ')';
        var directUrl = endpoint + '?_where=' + encodeURIComponent(whereClause) + '&_sort=-date&_size=20';
        var directResponse = await fetch(directUrl, {
          method: 'GET',
          headers: { 'accept': 'application/json' }
        });

        if (!directResponse.ok) {
          throw new Error('PhishStats HTTP ' + directResponse.status);
        }

        var directPayload = await directResponse.json();
        return Array.isArray(directPayload) ? directPayload : [];
      }

      async function checkUrlWithPhishStats(rawUrl) {
        var hostname = getHostname(rawUrl);
        if (!hostname) {
          return { rawUrl: rawUrl, hostname: '', count: 0, maxScore: 0, matchedHost: false };
        }

        var records = await queryPhishStatsByHost(hostname);
        var relevant = records.filter(function (item) {
          var recordUrl = (item && item.url ? String(item.url) : '').toLowerCase();
          return recordUrl.indexOf(hostname) !== -1;
        });

        var maxScore = relevant.reduce(function (acc, item) {
          var val = Number(item && item.score);
          return Number.isFinite(val) ? Math.max(acc, val) : acc;
        }, 0);

        return {
          rawUrl: rawUrl,
          hostname: hostname,
          count: relevant.length,
          maxScore: maxScore,
          matchedHost: relevant.length > 0
        };
      }

      async function analyser() {
        var txt = document.getElementById('input').value.trim();
        if (!txt) {
          alert('Veuillez coller du contenu à analyser.');
          return;
        }

        var out = document.getElementById('output');
        var scoreEl = document.getElementById('score');
        var verdict = document.getElementById('verdict');
        var short = document.getElementById('short');
        var details = document.getElementById('details');
        var advice = document.getElementById('advice');

        var score = 0;
        var reasons = [];
        var lowered = txt.toLowerCase();
        var bankScamFlags = 0;
        var suspiciousSenderDomains = [];

        var emailMatches = txt.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
        var senderEmails = Array.from(new Set(emailMatches.map(function (e) {
          return e.toLowerCase();
        })));

        if (senderEmails.length) {
          reasons.push('Adresse(s) e-mail détectée(s) dans le message.');
        }

        var riskyTlds = ['top', 'xyz', 'win', 'club', 'loan', 'vip', 'click', 'shop'];
        var disposableDomains = ['mailinator.com', 'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'yopmail.com'];
        var genericMailDomains = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'proton.me', 'protonmail.com'];
        var trustedBrands = {
          ameli: ['ameli.fr', 'assurance-maladie.fr'],
          impots: ['impots.gouv.fr', 'dgfip.finances.gouv.fr'],
          paypal: ['paypal.com', 'paypal.fr'],
          laposte: ['laposte.fr'],
          banque: ['credit-agricole.fr', 'societegenerale.fr', 'bnpparibas.com', 'labanquepostale.fr', 'caissedepargne.fr', 'banquepopulaire.fr', 'bred.fr']
        };

        senderEmails.forEach(function (email) {
          var domain = email.split('@')[1] || '';
          var tld = domain.split('.').pop() || '';

          if (domain.indexOf('xn--') !== -1) {
            score += 16;
            reasons.push('Domaine expéditeur en punycode détecté (' + domain + ').');
            suspiciousSenderDomains.push(domain);
          }

          if (riskyTlds.indexOf(tld) !== -1) {
            score += 14;
            reasons.push('Domaine expéditeur avec extension à risque (' + domain + ').');
            suspiciousSenderDomains.push(domain);
          }

          if (disposableDomains.indexOf(domain) !== -1) {
            score += 14;
            reasons.push('Domaine jetable détecté (' + domain + ').');
            suspiciousSenderDomains.push(domain);
          }

          if (/\d{4,}|-{2,}/.test(domain)) {
            score += 8;
            reasons.push('Domaine expéditeur inhabituel (' + domain + ').');
            suspiciousSenderDomains.push(domain);
          }

          if (/(banque|paiement|carte|ameli|impots|paypal|securite|opposition)/i.test(txt) && genericMailDomains.indexOf(domain) !== -1) {
            score += 12;
            reasons.push('Message sensible envoyé via messagerie générique (' + domain + ').');
            suspiciousSenderDomains.push(domain);
          }
        });

        Object.keys(trustedBrands).forEach(function (brandKey) {
          if (lowered.indexOf(brandKey) === -1 || !senderEmails.length) {
            return;
          }

          var allowedDomains = trustedBrands[brandKey];
          var hasMatchingSender = senderEmails.some(function (email) {
            var domain = email.split('@')[1] || '';
            return allowedDomains.some(function (allowed) {
              return domain === allowed || domain.endsWith('.' + allowed);
            });
          });

          if (!hasMatchingSender) {
            score += 16;
            reasons.push('Incohérence possible entre la marque citée («' + brandKey + '») et le domaine expéditeur.');
          }
        });

        var urgencyWords = ['urgent', 'immédiat', 'maintenant', 'dernière chance', 'action requise', 'sans délai', 'compte suspendu', 'immediatement'];
        urgencyWords.forEach(function (w) {
          if (lowered.indexOf(w) !== -1) {
            score += 18;
            reasons.push('Usage d\'urgence («' + w + '»).');
          }
        });

        var pressureWords = ['compte suspendu', 'dernière chance', 'bloqué', 'bloque', 'risque de fermeture'];
        pressureWords.forEach(function (w) {
          if (lowered.indexOf(w) !== -1) {
            score += 15;
            reasons.push('Pression émotionnelle détectée («' + w + '»).');
          }
        });

        var moneyWords = ['paiement', 'remboursement', 'transfert', 'argent', 'virement', 'gain'];
        moneyWords.forEach(function (w) {
          if (lowered.indexOf(w) !== -1) {
            score += 14;
            reasons.push('Mention d\'argent («' + w + '»).');
          }
        });

        var amountMatches = txt.match(/(?:\d{1,3}(?:[ .]\d{3})+|\d+)(?:[,.]\d{2})?\s?(?:€|eur)\b/gi);
        if (amountMatches && amountMatches.length) {
          score += Math.min(20, amountMatches.length * 8);
          reasons.push('Montant financier détecté (' + amountMatches.slice(0, 2).join(', ') + (amountMatches.length > 2 ? '…' : '') + ').');
          bankScamFlags += 1;
        }

        if (/(commande\s*n[°o]?|votre achat|paiement\s+(?:de|en\s+cours)|virement\s+de|op[eé]ration\s+(?:financi[eè]re|de\s+carte))/i.test(txt)) {
          score += 16;
          reasons.push('Scénario faux achat/paiement/virement détecté.');
          bankScamFlags += 1;
        }

        if (/(cr[eé]dit\s+agricole|bred|service\s+opposition|service\s+de\s+s[eé]curit[eé]|sos\s*carte|espace\s+personnel)/i.test(txt)) {
          score += 14;
          reasons.push('Référence bancaire/service sécurité potentiellement usurpée.');
          bankScamFlags += 1;
        }

        if (/(si\s+vous\s+n['’]?(?:e|é)tes\s+pas\s+[àa]\s+l['’]origine|si\s+vous\s+n['’]avez\s+pas\s+initi[eé]|si\s+non\s+autoris[eé]e|veuillez\s+contacter|appelez\s+imm[eé]diatement|contacter\s+vite)/i.test(txt)) {
          score += 18;
          reasons.push('Incitation à appeler rapidement après une opération prétendue.');
          bankScamFlags += 1;
        }

        if (/(nouvel\s+appareil|connexion\s+d['’]un|adresse\s+ip|24h\/24|appel\s+non\s+surtax[eé]|rapport[-\s]?\d{3,}|ref\s*:\s*[a-z0-9-]{4,}|carte\s*x{3,})/i.test(txt)) {
          score += 14;
          reasons.push('Format de faux “rapport sécurité” détecté (appareil/IP/référence).');
          bankScamFlags += 1;
        }

        if (bankScamFlags >= 2) {
          score += 14;
          reasons.push('Combinaison typique d\'arnaque bancaire par SMS.');
        }

        var urls = extractUrls(txt);
        var apiUnavailable = false;
        if (urls.length) {
          reasons.push('Lien(s) détecté(s) : ' + urls.length + '.');

          var suspiciousInfraRoots = ['clanweb.eu', 'ukit.me', 'framer.app', 'weebly.com', 'vercel.app'];
          var authLikeParams = ['_authentication', 'authentication', 'token', 'id_token_hint', 'session', 'ifkv', 'dsh', 'redeem', 'sourcedoc', 'originalpath', 'flowname', 'flowentry'];
          var baitBrands = ['orange.fr', 'google', 'onedrive', 'irs.gov', 'hotmart', 'paypal', 'ameli', 'impots.gouv.fr'];
          var criticalUrlMatches = 0;
          var suspiciousHostHits = 0;

          urls.forEach(function (rawUrl) {
            var loweredUrl = rawUrl.toLowerCase();
            var hostName = getHostname(rawUrl);
            var rootDomain = getRootDomain(hostName);
            var hasRedirectParam = false;
            var hasEncodedNestedUrl = false;
            var hasLongAuthToken = false;
            var hasBrandMismatch = false;
            var hasIpSigninCombo = false;

            var parsedUrl;
            try {
              parsedUrl = new URL(rawUrl);
            } catch (e) {
              parsedUrl = null;
            }

            if (parsedUrl && parsedUrl.protocol === 'http:') {
              score += 16;
              reasons.push('Lien non chiffré (HTTP) détecté.');
            }

            if (/\d{1,3}(?:\.\d{1,3}){3}/.test(rawUrl)) {
              score += 18;
              reasons.push('URL contenant une adresse IP.');
            }

            if (/\.(top|xyz|win|club|loan|vip)$/i.test(hostName)) {
              score += 12;
              reasons.push('Domaine à haut risque (' + hostName + ').');
            }

            if (suspiciousInfraRoots.indexOf(rootDomain) !== -1) {
              score += 18;
              reasons.push('Infrastructure d\'hébergement fréquemment abusée détectée (' + rootDomain + ').');
            }

            if (rawUrl.length > 120) {
              score += 12;
              reasons.push('URL anormalement longue.');
            }

            if (/(?:\?|&)(?:return_url|redirect|redirect_uri|next|continue|target|url)=/i.test(rawUrl)) {
              score += 24;
              reasons.push('Paramètre de redirection détecté (return_url/redirect/next).');
              hasRedirectParam = true;
            }

            if (/%3a%2f%2f/i.test(rawUrl)) {
              score += 14;
              reasons.push('URL encodée imbriquée détectée.');
              hasEncodedNestedUrl = true;
            }

            if (/(?:\?|&)(?:_authentication|token|auth|session|key)=/i.test(rawUrl) && /[a-f0-9]{24,}/i.test(rawUrl)) {
              score += 20;
              reasons.push('Jeton d\'authentification suspect dans l\'URL.');
              hasLongAuthToken = true;
            }

            if (parsedUrl) {
              var suspiciousParamCount = 0;
              parsedUrl.searchParams.forEach(function (paramValue, paramKey) {
                var key = String(paramKey || '').toLowerCase();
                var value = String(paramValue || '');

                if (authLikeParams.indexOf(key) !== -1) {
                  suspiciousParamCount += 1;
                }
                if (isHighEntropyValue(value)) {
                  suspiciousParamCount += 1;
                }

                var decodedValue = safeDecode(value).toLowerCase();
                if (decodedValue.indexOf('http://') !== -1 || decodedValue.indexOf('https://') !== -1) {
                  suspiciousParamCount += 1;
                }
              });

              if (suspiciousParamCount >= 2) {
                score += Math.min(24, suspiciousParamCount * 6);
                reasons.push('Paramètres URL suspects (jetons/valeurs encodées) détectés.');
              }
            }

            if (/^[a-z-]*\d{2,}[a-z0-9-]*\./i.test(hostName)) {
              score += 10;
              reasons.push('Sous-domaine potentiellement automatisé/suspect (' + hostName + ').');
            }

            if (isGeneratedSubdomain(hostName) && suspiciousInfraRoots.indexOf(rootDomain) !== -1) {
              score += 16;
              reasons.push('Sous-domaine généré sur plateforme fréquemment abusée (' + hostName + ').');
              suspiciousHostHits += 1;
            }

            var decodedUrl = safeDecode(rawUrl).toLowerCase();
            if ((decodedUrl.indexOf('orange.fr') !== -1 || loweredUrl.indexOf('orange.fr') !== -1) && hostName.indexOf('orange.fr') === -1) {
              score += 28;
              reasons.push('Marque/URL officielle citée en redirection mais domaine réel différent (' + hostName + ').');
              hasBrandMismatch = true;
            }

            baitBrands.forEach(function (brand) {
              if (decodedUrl.indexOf(brand) === -1 && loweredUrl.indexOf(brand) === -1) {
                return;
              }

              if (hostName.indexOf(brand) === -1) {
                score += 16;
                reasons.push('Référence à «' + brand + '» avec un domaine hôte différent (' + hostName + ').');
                hasBrandMismatch = true;
              }
            });

            if (/(login|secure|verify|account|auth|validation|signin|portail)/i.test(decodedUrl)) {
              score += 10;
              reasons.push('Chemin/paramètres typiques de phishing (login/secure/verify/auth).');
            }

            if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostName) && /(signin|login|servicelogin|identifier)/i.test(decodedUrl)) {
              score += 22;
              reasons.push('Adresse IP utilisée pour une fausse page de connexion.');
              hasIpSigninCombo = true;
            }

            if ((hasRedirectParam && hasEncodedNestedUrl && hasLongAuthToken) ||
                (hasRedirectParam && hasBrandMismatch && hasLongAuthToken) ||
                hasIpSigninCombo) {
              criticalUrlMatches += 1;
            }
          });

          var urlRootDomains = urls.map(function (item) { return getRootDomain(getHostname(item)); }).filter(Boolean);
          var repeatedRoots = urlRootDomains.filter(function (root, idx, arr) {
            return arr.indexOf(root) !== idx;
          });
          if (repeatedRoots.length) {
            score += 10;
            reasons.push('Répétition d\'un même domaine suspect dans plusieurs liens.');
          }

          if (urls.length >= 3 && (repeatedRoots.length || suspiciousHostHits >= 1)) {
            score += 12;
            reasons.push('Pattern de campagne détecté (multi-liens avec domaines/sous-domaines suspects).');
          }

          if (criticalUrlMatches > 0) {
            score = Math.max(score, 85);
            reasons.push('Signature critique de phishing détectée (redirection + jeton/usurpation).');
          }

          try {
            var phishChecks = await Promise.all(urls.slice(0, 3).map(function (rawUrl) {
              return checkUrlWithPhishStats(rawUrl);
            }));

            phishChecks.forEach(function (check) {
              if (check.matchedHost) {
                score += Math.min(30, 12 + check.count * 2);
                reasons.push('PhishStats: ' + check.count + ' signalement(s) trouvé(s) pour ' + check.hostname + '.');

                if (check.maxScore >= 8) {
                  score += 12;
                  reasons.push('PhishStats: score élevé détecté pour ' + check.hostname + ' (score max: ' + check.maxScore + ').');
                }
              }
            });
          } catch (err) {
            apiUnavailable = true;
          }
        }

        // Shortened links detection (bit.ly, tinyurl, t.co, goo.gl)
        if (/(bit\.ly|tinyurl|t\.co|goo\.gl)/i.test(txt)) {
          score += 12;
          reasons.push('Lien raccourci détecté (ex: bit.ly, tinyurl)');
        }

        var textWithoutUrls = txt.replace(/https?:\/\/[^\s<>")]+/gi, ' ');
        if (/(?:\+33|0)[1-9](?:[\s.-]?(?:\d{2}|xx)){4}/i.test(textWithoutUrls) || /\b\+?\d{7,15}\b/.test(textWithoutUrls)) {
          score += 8;
          reasons.push('Numéro de téléphone détecté');
        }

        if (/(admin|support|facture|paypal|impots|ameli|securite|opposition|banque)/i.test(txt)) {
          score += 10;
          reasons.push('Mention possible d\'usurpation de service');
        }

        var words = txt.split(/\s+/);
        var upperCount = words.filter(function (w) {
          return w.length > 2 && w === w.toUpperCase();
        }).length;
        if (upperCount > 3) {
          score += 6;
          reasons.push('Texte en majuscules');
        }

        score = Math.min(100, score);

        out.hidden = false;
        scoreEl.textContent = score + '%';
        // animate radial meter: store percent in CSS custom property (0-100)
        scoreEl.style.setProperty('--percent', String(score));
        // update conic-gradient explicitly for older browsers
        scoreEl.style.background = 'radial-gradient(closest-side, var(--panel) 74%, transparent 76% 100%), conic-gradient(var(--accent) ' + (score * 3.6) + 'deg, rgba(255,255,255,0.06) 0deg)';
        // small pop animation for UX
        scoreEl.classList.remove('pulse');
        if (score >= 60) {
          // add pulse for high risk
          void scoreEl.offsetWidth; // trigger reflow
          scoreEl.classList.add('pulse');
        }

        if (score < 25) {
          verdict.textContent = 'Faible risque';
          short.textContent = 'Peu d\'indices suspects.';
          scoreEl.className = 'meter safe';
        } else if (score < 60) {
          verdict.textContent = 'Risque modéré';
          short.textContent = 'Quelques éléments suspects — soyez prudent.';
          scoreEl.className = 'meter warn';
        } else {
          verdict.textContent = 'Risque élevé';
          short.textContent = 'Probable arnaque — ne pas répondre, bloquez et signalez.';
          scoreEl.className = 'meter danger';
        }

        if (reasons.length) {
          var senderHtml = '';
          if (senderEmails.length) {
            senderHtml = '<strong>Expéditeurs détectés :</strong><ul>' + senderEmails.map(function (sender) { return '<li>' + sender + '</li>'; }).join('') + '</ul>';
          }

          details.innerHTML = '<strong>Signes détectés :</strong><ul>' + reasons.map(function (r) { return '<li>' + r + '</li>'; }).join('') + '</ul>' + senderHtml;
        } else {
          details.innerHTML = '<strong>Signes détectés :</strong> Aucun signe clair.';
        }

        var adv = [];
        if (score < 25) adv.push('Aucune action urgente requise.');
        if (score >= 25) adv.push('Ne cliquez pas sur les liens et ne fournissez pas d\'informations.');
        if (bankScamFlags >= 2) adv.push('N\'appelez pas le numéro présent dans le SMS.');
        if (bankScamFlags >= 2) adv.push('Vérifiez la situation depuis l\'application ou le site officiel de votre banque.');
        if (bankScamFlags >= 2) adv.push('Contactez votre banque uniquement via le numéro officiel trouvé par vous-même.');
        if (score >= 60 && bankScamFlags >= 2) adv.push('Si vous avez déjà communiqué des infos ou validé une opération, alertez immédiatement votre banque.');
        if (senderEmails.length) adv.push('Vérifiez le domaine exact de l\'expéditeur (pas seulement le nom affiché).');
        if (suspiciousSenderDomains.length) adv.push('Le(s) domaine(s) suspect(s) détecté(s) : ' + Array.from(new Set(suspiciousSenderDomains)).slice(0, 3).join(', ') + '.');
        if (apiUnavailable && urls.length) adv.push('Vérification PhishStats indisponible pour le moment : réessayez ou vérifiez manuellement le lien.');
        if (score >= 60) adv.push('Bloquez, signalez et demandez de l\'aide professionnelle si nécessaire.');

        advice.innerHTML = '<strong>Recommandations :</strong><ul>' + adv.map(function (a) { return '<li>' + a + '</li>'; }).join('') + '</ul>';
      }