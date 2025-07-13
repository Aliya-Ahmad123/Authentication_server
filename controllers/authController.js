//create API EndPoint

import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

export const register = async (req, res)=>{
    const {name, email, password} = req.body;

    if(!name || !email || !password){
        return res.json({success: false, message:"Missing Details"})
    }

    try{

        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({succes: false, message:"User already exists"})
        }

   const hashedPassword = await bcrypt.hash(password, 10);

   //creating new user
   const user = new userModel({name,email,password:hashedPassword});
   //store user in database
   await user.save();

   //generate a token for authentication and send using cookies
   const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

   //and then add that token in cookie
   res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
   });

   //sending welcome email
   const mailOptions = {
    from: process.env.SENDER_EMAIL,
    to: email,
    subject:'Welcome to Edureka',
    text: `Welcome to Edureka. your account has been created with email id: ${email}`

   }

   await transporter.sendMail(mailOptions);

   return res.json({succes: true})

    } catch(error){
        res.json({success: false, message: error.message})
    }
}

export const login = async (req, res) =>{
    const {email,password} = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email and password are required'})
    }

    try{
      
     const user = await userModel.findOne({email})

     if(!user ){
        return res.json({succes: false, message: 'Invalid Email'})
     }

     const isMatch = await bcrypt.compare(password, user.password);

     if(!isMatch){
        return res.json({success: false, message: 'Invalid password'})
     }

     //generate  a token to logged in
     const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

   //and then add that token in cookie
   res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
   });




   return res.json({succes: true})



    }  catch(error){
      return res.json({success: false, message: error.message})  
    }

}


export const logout = async (req, res)=>{
    try{

        res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',

        })

        return res.json({succes: true, message:'Logged Out'})

    }  catch (error){
        return res.json({ success: false, message: error.message});
    }
}


//Send verification otp to the user's Email
export const sendVerifyOtp = async (req, res)=>{
    try{
         //userId to get user
       // const {userId}  = req.body;
            const userId = req.userId;
        const user = await userModel.findById(userId);

        if(user.isAccountVerified){
            return res.json({success: false, message: "Account Already Verified"})
        }

        //generate otp
     const otp = String(Math.floor( 100000 + Math.random() * 900000));

     //to save otp in database
     user.verifyOtp = otp;
     user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000

     await user.save();

     const mailOption = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject:'Account Verification OTP',
        text: `your OTP is ${otp}. Verify your account using this OTP.`

     }

     await transporter.sendMail(mailOption);

     res.json({success: true, message: 'Verification OTP Sent on Email'})


    } catch(error) {
        res.json({ success: false, message: error.message})
    }
}


export const verifyEmail = async (req, res) =>{
  //  const {userId, otp} = req.body;

  const { otp } = req.body;
  const userId = req.userId;


    if(!userId || !otp){
        return res.json({ success: false, message: 'Missing Details'})
    }

    try{
     
        const user = await userModel.findById(userId);

        if(!user){
            return res.json({ success: false, message: 'Missing Details'})
        }

        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({ success: false, message: 'Invalid OTP'})
        }

        if(user.verifyOtpExpireAt < Date.now()){
             return res.json({ success: false, message: 'OTP Expired'})
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({ success: true, message: 'Email verified successfully'})


    }catch (error){
        res.json({ success: false, message: error.message})
    }
}


//Check if user is authenticated
export const isAuthenticated = async (req, res)=>{
    try{
    return  res.json({succes: true})
    }  catch (error){
        res.json({succes: false, message: error.message});
    }  
}

//Send Password Reset OTP
export const sendResetOtp = async (req, res) =>{
    const {email} = req.body;

    if(!email){
        return res.json({succes: false, message: 'Email is required'})
    }

    try{

        const user = await userModel.findOne({email});
        if(!user){
             return res.json({succes: false, message: 'User not found'})
        }

         const otp = String(Math.floor( 100000 + Math.random() * 900000));

     //to save otp in database
     user.resetOtp = otp;
     user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000

     await user.save();

     const mailOption = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject:'Password Reset OTP',
        text: `your OTP for resetting your password is ${otp}.Use this OTP to proceed with resetting your password.`

     }

     await transporter.sendMail(mailOption);

     return  res.json({succes: true, message: 'OTP sent to your email'});


    }  catch (error){
        res.json({succes: false, message: error.message});
    }
}


//Reset User Password
export const resetPassword = async (req, res)=>{
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({ success: false , message: 'Email, OTP, and new Password are required'});
    }

    try{
     const user = await userModel.findOne({email});
     if(!user){
        return  res.json({succes: false, message: 'User not found'});
     }

    if(user.resetOtp === "" || user.resetOtp !== otp){
        return  res.json({succes: false, message: 'Invalid OTP'});
    }

    if(user.resetOtpExpireAt < Date.now()){
        return  res.json({succes: false, message: 'OTP Expired'});
    }

    //Incrypt password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;

    await user.save();

    return  res.json({succes: true, message: 'Password has been reset successfully'});

    }  catch(error){
     return  res.json({succes: false, message: error.message});
    }
}