# Downloader for Webshare
Features:
- Made to run in a container (tested with Docker).
- Queues files from Webshare.cz (WS) and then downloads them one by one.
- Manage the local repository - see the remaining disk space, delete individual files.
- The app consists of two components:
  - app.py - web UI (overview of local queue and downloaded files)
  - downloader.py - background worker (downloading files, reading the WS queue, removing files from WS queue)
- Both application components use a common sqlite database.
- Files can be added by:
  - providing the Direct Download link,
  - simply queuing the file using the WS [downloads list](https://webshare.cz/#/downloads) feature.
- When provided with WS username and password, the app will generate the WS token and use it to work with the WS download queue.
- WS Queue logic:
  1. File information is fetched from the WS download queue.
  2. If successfuly added to the local download queue, file is removed from the WS download queue.


# Home Assistant Integration

## HA configuration in configuration.yaml
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

## Gauge Card for Current Download Progress
```yaml
type: gauge
entity: sensor.download_percentage
needle: false
name: Stahování aktuálního souboru z WS
```

## Markdown Card for Download Queue Size Visualization
```yaml
type: markdown
content: >
  {% set count = states('sensor.download_queue_size') | int %} {% if count == 0
  %} 🗃️ *Žádné soubory* {% else %} **Počet souborů:** {{ count }}

  {% for i in range(count) %} 📄 {% endfor %} {% endif %}
title: Soubory čekající na stažení z WS
```
