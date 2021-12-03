### Example crontab entry for 30 expiry notification
/usr/bin/node /var/node/cert-monitor/index.js /var/node/cert-monitor/services.csv 30 > /dev/null
