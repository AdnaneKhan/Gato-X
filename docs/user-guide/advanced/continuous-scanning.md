# Using Gato-X for Continuous Scanning

Gato-X has features that make it useful for continously scanning thousands of repositories daily.

* Reusable Action Caching
* Webhook Notification
* Tunable configuration

## Reusable Action Caching

Gato-X performs analysis of all referenced reusable actions (even cross repository!) to identify vulnerabilities present within aciton.yml files.

This is an involved process because Gato-X will make one API request for each referenced reusable action. When scanning a large amount of repositor

## Webhook Notifications

Gato-X supports sending notifications to Slack webhooks if it detects vulnerability
comitted within the last 24 hours.
