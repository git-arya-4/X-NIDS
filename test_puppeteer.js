const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
  
  await page.goto('http://127.0.0.1:5000', {waitUntil: 'networkidle0'});
  
  await page.evaluate(() => {
    window.navigate('netmap');
  });
  
  await new Promise(r => setTimeout(r, 2000));
  
  const results = await page.evaluate(() => {
      const cvs = document.getElementById('netCanvas');
      const cont = document.getElementById('map-container');
      if (!cvs || !cont) return "NOT FOUND";
      return {
          cvsWidth: cvs.width,
          cvsHeight: cvs.height,
          cvsCssWidth: cvs.style.width,
          cvsCssHeight: cvs.style.height,
          contWidth: cont.clientWidth,
          contHeight: cont.clientHeight,
          display: window.getComputedStyle(cont).display
      };
  });
  
  console.log('Results:', results);
  
  await browser.close();
})();
