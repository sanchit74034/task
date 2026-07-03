import 'dotenv/config';
import express from 'express'
import mongoose from 'mongoose'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs';
import { User } from './src/models/user.schema';

const app = express();
app.use(express.json);

const userSchema = new Schema({
    email : {type : String, required : true, unique:true},
    password : {type : String, required : true},
    refreshToken : {type : String , default : null}
})



app.post('/register', async(req,res) =>{
    try{
        const{email,password} = req.body;
        const existingUser = await User.findone({email});
        if(existingUser) return res.status(400).json({message : "User Already Register"});

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUSer = new User({email , password :hashedPassword});
        await newUser.save();

        res.status(201).json({Message:"user register successfully"})
     }
     catch(error){
        res.status(500).json({message :"Registration failed"})
     }
});

app.post('/login',async(req,res)=>{
    try {
        const {email,password} = req.body;
        const user = await User.findOne({email,password})
        if(!user) return res.status(400).json({message : "invalid ceredentials"})

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) return res.status(400).json({message: "invalid ceredentials"});

        const accessToken = jwt.sign({userId: user._id},ACCESS_SECRET, {expiresIn:'1m'})
        const refreshToken = jwt.sign({userId: user._id},REFRESH_SECRET,{expiresIn:'7D'});

        res.cookie('refreshToken', refreshToken,{httpOnly : true , secure: true , maxAge : 7*24*60*60*1000})

    } catch (error) {
        res.status(500).json({error:"Login Failed"})
    }
})

app.post('/refresh-token',async (req,res)=>{
    const {refreshToken} = req.body;
    if(!refreshToken) return res.status(401).json({message:"token required"});

    const user = await User.findOne({refreshToken})
    if(!user) return res.status(401).json({message:"Invalid token "})
    
    jwt.verify(refreshToken , REFRESH_SECRET, (err,decode) =>{
        if(err) return res.status(401).json({message:"Token expires"})

    const newAccessToken = jwt.sign({id:user._id}, ACCESS_SECRET,{expiresIn:'1m'});
    res.json({accessToken:newAccessToken});        
    })
})

mongoose.coonect().then(()=> app.listen(3000, ()=>{
    console.log("server running on 3000");
}))


