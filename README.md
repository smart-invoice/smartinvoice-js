# Smart Invoice NodeJS SDK

Smart Invoice is a transportation layer which allow participants securely exchange documents between them.

API documentation: https://smart-invoice.github.io/smartinvoice-js/

# How to use it

    npm install --save smartinvoice-sdk


    import SmartInvoice from 'smartinvoice-sdk'

    var identity = SmartInvoice.createIdentity();
    var host = "https://api.difacturo.com"
    var config = { host: host}
    var smartinvoice = SmartInvoice.new(config, identity);
