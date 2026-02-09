![Docker Pulls](https://img.shields.io/docker/pulls/spidermila/wsdownloader)

# CZ readme
Find the ENG readme section below

## Stahovač pro Webshare
Aplikace, která:
- je primárně určena ke stahování souborů z Webshare.cz (WS), ale můžete manuálně přidat i odkazy odjinud,
- běží v Docker kontejneru,
- obsahuje seznam souborů ke stažení a tyto soubory postupně stahuje,
- spravuje lokální úložiště - zobrazuje místo na disku a umožňuje mazat stažené soubory,
- skládá se ze dvou součástí:
  - app.py - poskytuje webové uživatelské rozhraní
  - downloader.py - služba v pozadí, která sleduje seznam přání na WS a stahuje tyto soubory, nebo stahuje soubory manuálně přidané do seznamu souborů ke stažení
- obě součásti používají společnou sqlite databázi,
- soubory mohou být do seznamu přidány dvěma způsoby:
  - manuálně - jakýkoliv http či https odkaz, včetně "přímého odkazu" z WS
  - automaticky - stačí přidat soubor do [seznamu přání na WS](https://webshare.cz/#/downloads) a aplikace jej za vás stáhne. Je nutné se v aplikaci přihlásit vašimi WS přihlašovacími údaji. Pokud se soubor úspěšně přidá z WS seznamu přání do lokálního seznamu ke stažení, je automaticky z WS sezanmu přání odstraněn.

## Integrace do Home Assistant

### HA konfigurace v configuration.yaml
```yaml
sensor:
  - platform: rest
    name: Download Percentage
    unique_id: Download_percentage
    resource: http://<downloader server address>/links
    scan_interval: 10
    value_template: >
      {% if value_json.link_count | int > 0 %}
        {{ value_json.link | int }}
      {% else %}
        0
      {% endif %}
    unit_of_measurement: "%"

  - platform: rest
    name: Download Queue Size
    unique_id: Download_queue_size
    resource: http://<downloader server address>/links
    scan_interval: 10
    value_template: >
      {{ value_json.link_count | int }}
    unit_of_measurement: "files"
```

### Karta "Gauge" pro zobrazení průběhu stahování aktuálního souboru
```yaml
type: gauge
entity: sensor.download_percentage
needle: false
name: Stahování aktuálního souboru z WS
```

### Karta Markdown pro zobrazení velikosti seznamu souborů ke stažení
```yaml
type: markdown
content: >
  {% set count = states('sensor.download_queue_size') | int %} {% if count == 0
  %} 🗃️ *Žádné soubory* {% else %} **Počet souborů:** {{ count }}

  {% for i in range(count) %} 📄 {% endfor %} {% endif %}
title: Soubory čekající na stažení z WS
```

---
# EN readme

## Downloader for Webshare
Features:
- Primarily for downloading files from Webshare.cz (WS) but you can also queue files from elsewhere too.
- Made to run in a container (tested with Docker).
- Add files to a download queue and the app downloads them one by one.
- Manage the local repository - see the remaining disk space, delete individual files.
- The app consists of two components:
  - app.py - web UI (overview of local queue and downloaded files)
  - downloader.py - background worker (downloading files, reading the WS queue, removing files from WS queue)
- Both application components use a common sqlite database.
- Files can be added by:
  - providing the Direct Download link,
  - simply queuing the file using the WS [downloads list](https://webshare.cz/#/downloads) feature. Requires a WS login. If successfuly added to the local download queue, file is removed from the WS download queue.


## Home Assistant Integration

### HA configuration in configuration.yaml
```yaml
sensor:
  - platform: rest
    name: Download Percentage
    unique_id: Download_percentage
    resource: http://<downloader server address>/links
    scan_interval: 10
    value_template: >
      {% if value_json.link_count | int > 0 %}
        {{ value_json.link | int }}
      {% else %}
        0
      {% endif %}
    unit_of_measurement: "%"

  - platform: rest
    name: Download Queue Size
    unique_id: Download_queue_size
    resource: http://<downloader server address>/links
    scan_interval: 10
    value_template: >
      {{ value_json.link_count | int }}
    unit_of_measurement: "files"
```

### Gauge Card for Current Download Progress
```yaml
type: gauge
entity: sensor.download_percentage
needle: false
name: Current download progress
```

### Markdown Card for Download Queue Size Visualization
```yaml
type: markdown
content: >
  {% set count = states('sensor.download_queue_size') | int %} {% if count == 0
  %} 🗃️ *No files* {% else %} **Number of files:** {{ count }}

  {% for i in range(count) %} 📄 {% endfor %} {% endif %}
title: Files waiting for download
```
