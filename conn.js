const mysql = require('mysql2');
const db = mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'',
    database:'auth_db'
})
db.connect(err =>{
    if (err) {
        console.log(`there is error in mysql connection :${err}`);
    } else {
        console.log('connected to mysql');
    }
})
module.exports = db;