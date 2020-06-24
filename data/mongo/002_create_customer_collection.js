db = db.getSiblingDB('proddb'); // like 'use proddb'
db.createCollection('customer', {autoIndexId: true});
db.customer.createIndex({'email': 1}, {unique: true});