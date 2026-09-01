id: azure-storage-account-key

info:
  name: Azure Storage Account Key Disclosure
  author: reewardius
  severity: high
  metadata:
    verified: true
    max-request: 1
  tags: disclosure,azure,exposure,microsoft

http:
  - method: GET
    path:
      - '{{BaseURL}}'

    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - 'AccountKey='
          - 'DefaultEndpointsProtocol'
        condition: and
        case-insensitive: true

      - type: regex
        part: body
        regex:
          - '(?i)[A-Za-z0-9+/]{40,100}=='
