import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv'
import User from './models/User.js'
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from 'cors'
const app = express()
dotenv.config()
mongoose.connect(process.env.CONNECTION_URL, {
  useNewUrlParser: true, useUnifiedTopology: true
})
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(cors())
const secret = 'tarsh123';

const auth = async (req, res, next) => {
  try {
    const token = JSON.parse(req.headers.authorization);
    // console.log(token);


    
     const decodedData = jwt.verify(token, secret);
    //  console.log(decodedData);

      req.email = decodedData?.email;
      req.id=decodedData?.id

    next();
  } catch (error) {
    console.log(error);
  }
};

app.post('/signup', async (req, res) => {

  const {firstName,lastName,email,password}=req.body
  // console.log(req.body);
  try {
    const olduser=await User.findOne({email:email})
    if (olduser) {
      res.status(400).json({status:false,message:'Email already registered'})
    }
    else{
      const hashedPassword = await bcrypt.hash(password, 12);
      const newUser=await User.create({name:`${firstName} ${lastName}`,email,password:hashedPassword})
      const token = jwt.sign( { email: newUser.email, id: newUser._id }, secret, { expiresIn: "30d" } );
      res.status(201).json({ name:newUser.name,bio:newUser.bio, token });
    
  }} catch (error) {
    console.log(error);
    res.status(400).json({status:false,message:'Something went wrong'})
  }
  }
)

app.get('/',(req,res)=>{
  res.json({hello:'hello'})
})
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  // console.log(req.body);
  try {
    const oldUser = await User.findOne({ email });

    if (!oldUser) return res.status(404).json({ message: "User doesn't exist" });

    const isPasswordCorrect = await bcrypt.compare(password, oldUser.password);

    if (!isPasswordCorrect) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ email: oldUser.email, id: oldUser._id }, secret, { expiresIn: "30d" });
// console.log(oldUser);
    res.status(200).json({ name:oldUser.name,bio:oldUser.bio, token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Something went wrong" });
  }
})
app.post('/update',auth, async (req, res) => {
  const { name,bio} = req.body;
  const email=req.email
  const id=req.id
  // console.log(email);
  try {
    await User.updateOne({ email }, { $set: {bio,name } })
    res.status(200).json({ success:true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ success:false });
  }
})

const PORT=process.env.PORT || 5001;
mongoose.connect(process.env.CONNECTION_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => app.listen(PORT, () => console.log(`Server Running on Port: ${PORT}`)))
  .catch((error) => console.log(`${error} did not connect`));