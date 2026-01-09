require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const express = require('express');
const app = express();
const db = require('./conn');
const path = require('path');
const port = 8000;
app.use(express.json())
app.use(express.static(path.join(__dirname,'public')))

//------------for registering------------------- 
app.post('/api/newUser',async (req,res)=>{
    const {email,password,permission} = req.body;
     if(req.body.email==""||req.body.permission==""){ //check if body is empty
        return res.status(400).json({message:`no email or password entered`})
    }
    const saltRound = 10;
    const hashedPassword = await bcrypt.hash(password,saltRound);

     db.query('insert into users(email,password,permission) values(?,?,?)',[email,hashedPassword,permission],(err,rows)=>{
        if(err){
           res.json({message:`${err}`,status:'bad'});
        }else{
        res.json({message:`registered successfully`,status:'ok'})
        }
    })
    
})

//-----------for loging in-----------------
app.post('/api/login',(req,res)=>{
     const {email,password} = req.body;
    if(!email|| !password){
        return res.json({message:'please enter email and password'})
    }

        db.query('select * from users where email=?',[email],async(err,rows)=>{
        if (err) {
              return res.status(400).json({message:'there is error on database' + err})
        }
        if (rows.length == 0) {
            return res.status(404).json({message:'the email or username does not exist'})
        }
        const user = rows[0];
        const match = await bcrypt.compare(password,user.password);
         if (!match) {
             return res.status(401).json({message:'incorrect password'})
        }
        const token = jwt.sign({email:user.email,permission:user.permission},
            process.env.JWT_SECRET,
            {expiresIn:'1h'}
        )
        res.json({message:'logged in',token:token,nextPage:'dashboard.html'});

    })
})

//---------------api to verify and authorize-------------------
function verifyToken(req,res,next){
    if(!req.headers['authorization']) return  res.json({message:'no token provided'});
    const token = req.headers['authorization'].split(' ')[1];

    jwt.verify(token,process.env.JWT_SECRET,(err,decoded)=>{
        if(err) return res.json({message:'invalid token'});
        req.user = decoded;
        next()
    })
}
app.get('/api/verify',verifyToken,(req,res)=>{
    if(req.user.permission == 'admin'){
        res.json({message:'you are admin'})
    }else{
        res.json({message:'you are regular user'})
    }

})
app.listen(port,()=>{
    console.log(`connected to express server ${port}`);
})