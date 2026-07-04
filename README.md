# 🩺 DoctorRM — web

Veřejný hosting webové aplikace **DoctorRM** (CRM lékařů ČR pro Váš Praktik).

Toto repo obsahuje **jen hotový web** — HTML/JS a datový soubor `data/data.enc`,
který je **šifrovaný (AES‑256‑GCM) a bez hesla nečitelný**. Zdrojové kódy,
surová data a build skripty jsou v privátním repozitáři `VP-nakupy`.

Web běží na GitHub Pages: **https://borskypdx-ux.github.io/doctorrm/**
Přístup je chráněný heslem (zadává se po otevření stránky).

Data se aktualizují přenosem nového `data/data.enc` z privátního repa
(automaticky přes workflow *Data refresh*, pokud jsou nastavené secrety
`PAGES_REPO` + `PAGES_TOKEN`, viz `DEPLOY.md` v privátním repu).

`.nojekyll` zajišťuje, že GitHub Pages servíruje soubory beze změn.
