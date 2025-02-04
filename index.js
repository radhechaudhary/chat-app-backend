import express from "express";
import cors from "cors"
import bodyParser from "body-parser";
import jsonwebtoken from "jsonwebtoken";
import pg from 'pg'
import verifyTokenMiddleware from "./verifyToken.js";
import { createServer } from "http";
import { Server } from "socket.io";
import bcrypt from 'bcryptjs';
import users from "./user_socket.js";
import users_online from "./users_online.js";
import multer from "multer";
import {v2 as cloudinary} from "cloudinary";
import { createReadStream } from "streamifier";
import { configDotenv } from "dotenv";

const PORT=8058;
const app=express();
// configDotenv();
app.use(cors({
    origin: ["http://localhost:3000","https://chat-app-frontend-two-gold.vercel.app"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
}));
  
  app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true })); //body parser to encode body data from frontend
app.use(bodyParser.json());
app.use(express.json());
const server = createServer(app);
const io = new Server(server, {
    cors: {
      origin: ["http://localhost:3000","https://chat-app-frontend-two-gold.vercel.app"],
      methods: ["GET", "POST"],
      credentials: true,
    },
    transports: ["websocket", "polling"], // ✅ Allow both WebSocket & polling
  });

cloudinary.config({
    cloud_name:"dtoym7pet",
    api_key:"571783941667238",
    api_secret:"g8jU1T7FFL2YE3Xbs5D_5Yfmp24"
})

//setup multer
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const connectionString= "postgresql://postgres:HfdKaiaLwLwTxOYRtdgUnHpYaqGqcAqA@junction.proxy.rlwy.net:21476/railway"
const db=new pg.Client({
    connectionString,
    ssl: {
        rejectUnauthorized: false, // Required for some cloud databases like Railway
    }
})
db.connect();

app.get("/", (req,res)=>{
    res.send("hello")
})

io.on('connection',(socket)=>{  // socket connection
    const userId = socket.handshake.query.userId;
    if(userId){
        users[userId] = socket.id;
        active_users[userId]=true;
        users_online[userId]=true;
        console.log(`user ${userId} got connected`)
        io.emit('update_status_list', users_online);
    }
      socket.on("disconnect", (reason) => {
        // console.log(`❌ User disconnected: ${socket.id}, Reason: ${reason}`);
        
        // Remove user from active list

        const userId=Object.keys(users).find(key => users[key] === socket.id);
        console.log(`user ${userId} got disconnected`)
        delete active_users[userId];
        users_online[userId]=false;
        io.emit('update_status_list', users_online);

    });
      socket.on('get_saved_messages', async(username)=>{
        if(username){
            const data=await db.query('select new_messages from users where username=$1', [username]);
            const messages=data.rows[0].new_messages; 
            if(messages) {
                await db.query('update users set new_messages=$1 where username=$2',['{}', username]);
                Object.keys(messages).map((username)=>{
                    messages[username].map((message)=>{
                        io.to(socket.id).emit('privateMessage', {username:username, ...message});
                    })
                })     
            } 
             
        }  
      });
      socket.on('newChat',async(searchingValue)=>{  // search for the username
        const data=await db.query('select username, name, profilephoto, bio from users where username LIKE $1',[`%${searchingValue}%`]);
        if(data.rows.length>0){
            io.to(socket.id).emit('AddnewChat', data.rows[0])
        }
        else{
            io.to(socket.id).emit('AddnewChat',{}) 
        }
      })
      socket.on('update_status', (username, update)=>{ // update online users list
        users_online[username]=update;
        io.emit('update_status_list', users_online);  // send list to every user
      })
      socket.on('update_active_status_false',(username)=>{
        active_users[username]=false;
      })
      socket.on('typing', (recieverUsername, username)=>{
        if(recieverUsername.members){
            recieverUsername.members.map((user)=>{
                if(user.username!==username){
                    io.to(users[user.username]).emit('UserTyping', {[recieverUsername.username]:true});
                }   
            })
        }
        else io.to(users[recieverUsername]).emit('UserTyping', {[username]:true});
      })
      socket.on('stoppedTyping', (recieverUsername, username)=>{
        if(recieverUsername.members){
            recieverUsername.members.map((user)=>{
                io.to(users[user.username]).emit('UserTyping', {[recieverUsername.username]:false});
            })
        }
        else io.to(users[recieverUsername]).emit('UserTyping', {[username]:false});
      })
      socket.on('privateMessage', async ({recieverUsername, senderUsername, message, time})=>{  // sending messages
        if(active_users[recieverUsername]){
            io.to(users[recieverUsername]).emit('UserTyping', {[senderUsername]:false});
            io.to(users[recieverUsername]).emit('privateMessage',  { username:senderUsername,  message: message, time:time});
        }
        else{
            const data=await db.query("select new_messages from users where username=$1",[recieverUsername]);
            var savedMessages=data.rows[0].new_messages;
            const date=new Date();
            const time= date.getHours() +":"+ date.getMinutes();
            if(savedMessages[senderUsername]){
                savedMessages[senderUsername]=[...savedMessages[senderUsername], { sentBy: "partner", message, time:time }]
                await db.query('update users set new_messages=$1 where username=$2',[savedMessages, recieverUsername]);
            }
            else{
                savedMessages[senderUsername]=[{ sentBy: "partner", message, time:time}];
                await db.query('update users set new_messages=$1 where username=$2',[savedMessages, recieverUsername]);
            }
        }
         
      })
      socket.on('makeGroup', ({groupList, username, groupName, admin, time}) =>{ // make Group
        groupList.map((member)=>{
            io.to(users[member.username]).emit('addInGroup',  { groupName:groupName, username:username, members:groupList, admin:admin });
        })
      })
      socket.on('groupMessage', ({recieverUsers, groupName, username,  senderUsername, senderName, message, time })=>{
        recieverUsers.map(async(recieverUsername)=>{
            
            if(active_users[recieverUsername.username] && recieverUsername.username!==senderUsername){
                io.to(users[recieverUsername.username]).emit('UserTyping', {[senderUsername]:false});
                io.to(users[recieverUsername.username]).emit('groupMessage',  {username:username,  name:groupName, sender:senderName,  message: message, time:time});
            }
            else if(recieverUsername!==senderUsername){
                const data=await db.query("select new_messages from users where username=$1",[recieverUsername.username]);
                var savedMessages=data.rows[0].new_messages;
                const date=new Date();
                const time= date.getHours() +":"+ date.getMinutes();
                if(savedMessages[groupName]){
                    savedMessages[groupName]=[...savedMessages[groupName], { sentBy: "partner", message, time:time }]
                    await db.query('update users set new_messages=$1 where username=$2',[savedMessages, recieverUsername.username]);
                }
                else{
                    savedMessages[groupName]=[{ sentBy: "partner", message, time:time}];
                    await db.query('update users set new_messages=$1 where username=$2',[savedMessages, recieverUsername.username]);
                }
            }
        })
      })
      socket.on('update_data', async (chatlist) => {
        let updated_list = [];
        if (chatlist.length > 0) {
          // Use Promise.all to handle all async operations
          updated_list = await Promise.all(
            chatlist.map(async (user) => {
                if(user.type==='group'){
                    return user;
                }
              const result = await db.query(
                'select username, name, profilephoto, bio from users where username=$1',
                [user.username]
              );
              return {...result.rows[0], unread:user.unread, type:user.type, unreadMessagesCount:user.unreadMessagesCount}; // Return the fetched user data
            })
          );
        }
        io.to(socket.id).emit('update_data', updated_list); // Send the updated list back to the client
      });  
      socket.on('unregister', (userId)=>{ //  unregister
        delete active_users[userId];
        delete users_online[userId];
        delete users[userId];
      })
})

app.post('/login', async(req, res)=>{  //login route
    const username=req.body.username;
    const password=req.body.password;
    try{
        const data=await db.query("select password, sr_no, name, profilephoto from users where username=$1",[username]);
        const isMatch = await bcrypt.compare(password, data.rows[0].password);
        if(isMatch){
            const secretKey="h8u5896utri3i90a(%(Tfi*(%)))";
            const payload={
                userId:data.rows[0].sr_no,
                username:username
            }
            const token = jsonwebtoken.sign(payload, secretKey);
            const a=await db.query("update users set token=$1 where username=$2",[ token, username ])
            res.json({status:"valid",profilephoto:data.rows[0].profilephoto, username:username, name:data.rows[0].name, token:token});
        }
        else{
            res.send("password not valid")
        }
    }
    catch(err){
        console.log(err)
        res.send("username not found")
    }
    
})
app.post('/signup', async(req, res)=>{   // signUp route
    const name=req.body.name;
    const username=req.body.username;
    const password=req.body.password;
    if((password.length<8) || (!password.includes("_") && !password.includes("@") && !password.includes("#") && !password.includes("&") && !password.includes("-") && !password.includes("%") && !password.includes("$") && !password.includes("*"))){
        res.send("password must have 8 characters and must include symbols like @#$%*&")
      }
      else{
    try{
        const saltRounds = 10; // Higher rounds = more security but slower
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const data=await db.query("insert into users (name, username, password) values($1,$2,$3) returning sr_no",[name, username, hashedPassword]);
        const secretKey="h8u5896utri3i90a(%(Tfi*(%)))";
        const payload={
            userId:data.rows[0].sr_no,
            userId:4,
            username:username
        }
        const token = jsonwebtoken.sign(payload, secretKey);
        const a=await db.query("update users set token=$1, new_messages=$3 where username=$2",[ token,  username, '{}' ])
        res.json({status:"valid", username:username, token:token});
        }
    catch(err){
        console.log(err)
        res.send("username already present");
    }}
})

app.post('/upload-profile-photo',  upload.single('file'), async (req, res)=>{
    const {username, token}=req.body;
    try {
        if (!req.file || !req.file.buffer) {
            return res.json({status:'no file'})
        }
        // Upload to Cloudinary with transformations
        const result =  cloudinary.uploader.upload_stream(
          {
            folder: 'profile_photos', // Optional folder in Cloudinary
            quality: 'auto',           // Automatic quality optimization (good for web)
            fetch_format: 'auto',      // Automatically selects the best format (e.g., WebP, JPEG, PNG)
            width: 700,                // Resize to width of 800px (you can change this as needed)
            crop: 'scale',            // Scaling crop mode (maintains aspect ratio)        
          },
          async (error, uploadResult) => {
            if (error) {
                console.log(error.message)
                return res.status(500).send('Error uploading to Cloudinary: ' + error.message);
            }
            // save the image URL after successful upload
            console.log('uploaded succesfully')
            await db.query("update users set profilephoto=$1 where username=$2",[uploadResult.secure_url, username])
            res.json({status:'valid', photo_url:uploadResult.secure_url}) 
          }
        );
        console.log('Uploading image to Cloudinary...');
        // Pipe the file from Multer directly to Cloudinary
        createReadStream(req.file.buffer).pipe(result);
        
      } catch (error) {
        console.error(error.message);
        res.status(500).send('Error uploading file');
      } 
   
})
app.post('/edit-profile',   upload.single('file'), verifyTokenMiddleware, async(req, res) => {
    const { username, name, bio, token } = req.body;
    try {
        // Update user's name and bio in the database
        await db.query("update users set name=$1, bio=$2 where username=$3", [name, bio, username]);
        // Get the current profile photo URL
        const data = await db.query("select profilephoto from users where username=$1", [username]);
        const url = data.rows[0].profilephoto;
        // Function to extract the public ID from the URL
        if(url){
            function extractPublicIdFromUrl(url) {
                const parts = url.split('/'); // Split the URL by '/'
                const index = parts.findIndex((part) => part === 'upload'); // Locate "upload" in the URL
                const publicIdWithFolder = parts.slice(index + 1).join('/'); // Get everything after "upload"
                const publicId = publicIdWithFolder.replace(/v\d+\//, '').split('.')[0]; // Remove version (e.g., v1736504088/) and file extension
                return publicId;
            }
            const publicId = extractPublicIdFromUrl(url);
            try{
                cloudinary.api.delete_resources(
                    [publicId], // Array of public IDs
                    { type: 'upload'},                     // Optional: type of resource
                    (error, result) =>{                    // Callback function
                        if (error) {
                            console.error('Error deleting resources:', error);
                        } 
                    }
                );
            }
            catch(error){
                console.log(error);
            } 
        }
        try {
            if (!req.file || !req.file.buffer) {
                return res.status(500).send('Error uploading to Cloudinary: ' + error.message);
            }
            // Upload to Cloudinary with transformations
            const result =  cloudinary.uploader.upload_stream(
              {
                folder: 'profile_photos', // Optional folder in Cloudinary
                quality: 'auto',           // Automatic quality optimization (good for web)
                fetch_format: 'auto',      // Automatically selects the best format (e.g., WebP, JPEG, PNG)
                width: 700,                // Resize to width of 800px (you can change this as needed)
                crop: 'scale',             // Scaling crop mode (maintains aspect ratio)             
              },
              async (error, uploadResult) => {
                if (error) {
                    console.log(error.message)
                    return res.status(500).send('Error uploading to Cloudinary: ' + error.message);
                }
                // save the image URL after successful upload
                await db.query("update users set profilephoto=$1 where username=$2",[uploadResult.secure_url, username])
                res.json({status:'valid', photo_url:uploadResult.secure_url}) 
              }
            );
            // Pipe the file from Multer directly to Cloudinary
            createReadStream(req.file.buffer).pipe(result);
            
          } catch (error) {
            console.error(error.message);
            res.status(500).send('Error uploading file');
          }     
    } catch (err) {
        console.log('Error in database update:', err);
        res.send("Error");
    }
});


app.post('/authenticate-user', verifyTokenMiddleware, async(req, res)=>{
   const {username}=req.body;
   const token = req.headers.authorization?.split(' ')[1];
   try{
    const data=await db.query("select token from users where username=$1",[username])
        if( data.rows.length>0 && data.rows[0].token===token){
            res.json({status:'valid'})
        }
        else{
            res.json({status:'error'})
        }
    }
    catch(err){
        console.log(err)
    }   
})

server.listen(PORT,()=>{
    console.log(`connected on port ${PORT}`);
})


const active_users={};