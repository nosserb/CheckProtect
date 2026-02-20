

      'use strict';

      function clearAll() {
        document.getElementById('input').value = '';
        document.getElementById('output').hidden = true;
      }

      function analyser() {
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

        var urgencyWords = ['urgent', 'immédiat', 'maintenant', 'dernière chance', 'action requise', 'sans délai', 'compte suspendu', 'compte suspendu'];
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

        var urlMatch = txt.match(/https?:\/\/[^\s]+/i);
        if (urlMatch) {
          var host = urlMatch[0];
          if (/\d{1,3}(?:\.\d{1,3}){3}/.test(host)) {
            score += 18;
            reasons.push('URL contenant une adresse IP');
          }
          if (/\.(top|xyz|win|club|loan|vip)/i.test(host)) {
            score += 12;
            reasons.push('Domaine à haut risque');
          }
        }

        // Shortened links detection (bit.ly, tinyurl, t.co, goo.gl)
        if (/(bit\.ly|tinyurl|t\.co|goo\.gl)/i.test(txt)) {
          score += 12;
          reasons.push('Lien raccourci détecté (ex: bit.ly, tinyurl)');
        }

        if (/\+?\d{6,}/.test(txt)) {
          score += 8;
          reasons.push('Numéro de téléphone détecté');
        }

        if (/(admin|support|facture|paypal|impots|ameli|securite)/i.test(txt)) {
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
        scoreEl.style.background = 'conic-gradient(var(--accent) ' + (score * 3.6) + 'deg, rgba(255,255,255,0.04) 0deg)';
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
          details.innerHTML = '<strong>Signes détectés :</strong><ul>' + reasons.map(function (r) { return '<li>' + r + '</li>'; }).join('') + '</ul>';
        } else {
          details.innerHTML = '<strong>Signes détectés :</strong> Aucun signe clair.';
        }

        var adv = [];
        if (score < 25) adv.push('Aucune action urgente requise.');
        if (score >= 25) adv.push('Ne cliquez pas sur les liens et ne fournissez pas d\'informations.');
        if (score >= 60) adv.push('Bloquez, signalez et demandez de l\'aide professionnelle si nécessaire.');

        advice.innerHTML = '<strong>Recommandations :</strong><ul>' + adv.map(function (a) { return '<li>' + a + '</li>'; }).join('') + '</ul>';
      }