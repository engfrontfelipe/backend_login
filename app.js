require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

const User = require('./models/User')

//Public Route
app.get("/", (req, res) => {
    res.status(200).json({message: "Bem vindo a nossa API."})
});

app.get("/user/:id", checkToken, async (req, res) => { 
    const id = req.params.id;
    const user = await User.findById(id, '-password')
        
        if(user){
            res.status(200).json({user})
    
        }else{
            return res.status(404).json({msg: "Usuario nao encontrado"})
    
        }
});

function checkToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg: "Acesso negado"})
    }

    try {
        const secret = process.env.SECRET
        
        jwt.verify(token, secret)
    } 
    
    catch (err) {
        res.status(401).json({msg:"token inválido"})
    }


}


//Rota para criação de usuário 
app.post("/auth/register", async (req, res) => {
    const {name, email, password, confirmPassword} = req.body 

    if(!name){
        return res.status(422).json({msg: "O nome é obrigatório!"})
    };

    if(!email){
        return res.status(422).json({msg: "O email é obrigatório!"})
    };
    
    if(!password){
        return res.status(422).json({msg: "A senha é obrigatória!"})
    };

    if(password !== confirmPassword){
        return res.status(422).json({msg: "As senhas não conferem!"})    
    };

    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({msg: "E-mail já cadastrado, por favor digite um novo."})    

    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

   //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try{
        user.save()
        res.status(200).json('Usuário cadastrado com sucesso!')
    }
    catch(err){
        res.status(500).json({msg: "Tente novamnet mais tarde."})

    }

});

app.post("/auth/login", async (req, res) => {
    const {password, email} = req.body;

    if(!email){ return res.status(422).json({msg: "O campo de email não pode ficar vazio."})};
   
    if(!password){return res.status(422).json({msg: "O campo de senha não pode ficar vazio."})};

    //if user exist
    const user = await User.findOne({email: email})

    if(!user){
        return res.status(422).json({msg: "Usuário não encontrado"})    

    }

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        res.status(422).json({msg: "Senha incorreta."})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id
        }, secret)

        res.status(200).json({msg: "Autenticaçao realizada com sucesso!", token})
    }
    catch(err){
        console.log(err);
        res.status(500).json({msg: "Tente novamnet mais tarde."})

    }

});



const db_user = process.env.DB_USER;
const db_password = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${db_user}:${db_password}@cluster0.agt4jjr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
.then(() => {
    app.listen(3333, () => {
    console.log('Server is running in port http://localhost:3333 and connect for database')});

}).catch((err) => {console.log(err);
})
