
const Users = require("./Users.json");

const express = require('express');
const cors = require('cors');
const app = express();
const jwt = require('jsonwebtoken');
const verifyToken = require("./middleware/auth");
require('dotenv').config();

app.use(express.json());
app.use(cors({
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
  
// Imitating database
let refreshTokens = [];

app.listen(process.env.PORT || 8080 ,() => console.log(`listening on port ${process.env.PORT}`));

const generateAccessToken = (username) => {
    return jwt.sign({username}, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: '1h' });
}

const generateRefreshToken = (username) => {
    return jwt.sign({username},process.env.REFRESH_TOKEN_SECRET_KEY, { expiresIn: '1h' });
}

app.post('/login',(req,res) => {
    const [username,password] = [req.body.username , req.body.password ];
    if (Users.hasOwnProperty(username)) {
        if(Users[username] === password){
            const accessToken = generateAccessToken(username);
            const refreshToken = generateRefreshToken(username);
            refreshTokens.push(refreshToken);
            res.status(200).json({username:username,accessToken,refreshToken,message:"Logged In"})
        }

        else{
            res.status(401).json({message:"Incorrect Password"})
        }
    }
    else{
        res.status(401).json({message:"User does not exist"})
    }
})

app.post("/refresh",(req,res) => {
    const refreshToken = req.body.refreshToken;

    if(!refreshToken) return res.status(401).json({message:"You are not authenticated"});

    if(!refreshToken.includes(refreshToken)){
        return res.status(401).json({message:"Refresh token not valid"});
    }

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET_KEY, (err, decoded) => {
        if (err) {
          return res.status(401).json({ message: err});
        }
        const newAccessToken = generateAccessToken(decoded.username);
        const newRefreshToken = generateRefreshToken(decoded.username);

        refreshTokens.push(newRefreshToken);

        res.status(200).json({accessToken:newAccessToken,refreshToken:newRefreshToken})
      });

})

app.post("/logout",verifyToken,(req,res) => {
    const refreshToken = req.body.refreshToken;

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken)

    res.status(200).json({message:"Logged out successfully"});
})

app.get("/dashboardData",verifyToken,(req,res) => {
    res.status(200).json({username:req.user.username});
})