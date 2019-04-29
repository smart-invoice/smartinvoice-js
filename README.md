# Smart Invoice NodeJS SDK

Smart Invoice is a transportation layer which allow participants securely exchange documents between them.

API documentation: https://smart-invoice.github.io/smartinvoice-js/

# How to use it

    npm install --save smartinvoice-sdk


     // ES6 project
     import SmartInvoice from 'smartinvoice-sdk';

     // or below
     var SmartInvoice = require("smartinvoice-sdk").default

     var identity = SmartInvoice.createIdentity();
     var host = "https://api.difacturo.com"
     var config = { host: host}
     var smartinvoice = new SmartInvoice(config, identity);
