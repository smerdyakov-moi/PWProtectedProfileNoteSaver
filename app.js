const cookieParser = require('cookie-parser')
const express = require ('express')
const app = express()
const path = require ('path')
const userModel = require ('./Models/user')
const bcrypt = require ('bcrypt')
const jwt = require ('jsonwebtoken')
const fs = require ('fs')

app.set("view engine","ejs")
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(express.static(path.join(__dirname, 'public')))
app.use(cookieParser())

app.get('/',(req,res)=>{
    res.render('CreateUserPage')
})


app.post('/create', async (req,res)=>{
    const {username,email,password,age,image} = req.body
    let hash_pw = await bcrypt.hash(password,10) // because the bcrypt is asynchronous method

    let createdUser = await userModel.create({
        username,email,password:hash_pw,age,image
    })
    fs.mkdir(`./Folders/${createdUser._id}`,{recursive:true},(err)=>{})
    let token = jwt.sign({email:`${email}`}, "Secret")
    res.cookie("token",token)

    res.redirect('/userSitePage')
})

app.get('/logout',(req,res)=>{
    res.cookie("token","")
    res.redirect("/")
})

app.get('/login',(req,res)=>{
    res.render('LoginPage')
})

app.post('/login',async (req,res)=>{

    let user = await userModel.findOne({email:req.body.email})
    if (!user) res.send('Something went wrong')
    
    bcrypt.compare(req.body.password, user.password, function(err, result) {
        if (result) {
            
            let token = jwt.sign({email: user.email, id: user._id}, "Secret")
            res.cookie("token",token)
            res.redirect('/userSitePage')
        } else {
            res.send('Not Logged in /:')
        }
});



})

app.get('/userSitePage', checkAuth, async (req,res)=>{
    //res.send(req.user)
    let userx = await userModel.findOne({email:`${req.user.email}`})
    res.render('UserSitePage',{userx})
    
})


function checkAuth(req, res, next) {
    const token = req.cookies.token; // 1. Get token from browser cookie
    if (!token) {
        return res.status(401).send("Access Denied: No Token Provided"); // 2. Reject if no token
    }

    try {
        const verified = jwt.verify(token, "Secret"); // 3. Verify token using secret key
        req.user = verified; // 4. If valid, attach user info (from token) to req object
        next(); // 5. Call next() to allow request to continue
    } catch (err) {
        res.status(400).send("Invalid Token"); // 6. If token is invalid or expired
    }
}



//Added

app.get('/editProfile/:id',checkAuth, async (req,res)=>{
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")
    let user = await userModel.findOne({_id:req.params.id}) //We are using findOne here so we can return only an object . Thus, no destructuring is needed \
    // {user} unlike the previous /read route where {users:allusers} had to be implemented

    res.render('UpdatePage',{user}) //The update page will be rendered along with the object 'user' we are deleting
})

app.post('/update/:userid', checkAuth, async(req,res)=>
{
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")
    let {username,email,image} = req.body //Stores the updated (if any) record
    let user = await userModel.findOneAndUpdate({_id:req.params.userid}, {username,image}, {new:true}) // Updates the user
    res.redirect('/userSitePage') // Redirects to the read page
})

app.get('/deleteProfile/:ID',checkAuth, async(req,res)=>{
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")
    const {ID} = req.params // req.params is used only when dynamic routing is applied. Otherwise, any thing dealing with the frontend aspect will normally
    //result in req.body as seen in the /create route where the client enters

    let deletedUser = await userModel.findOneAndDelete({_id:ID}) //Simple Deletion of the record
    res.cookie("token","")
    fs.rmdir(`./Folders/${ID}`,{recursive:true},(err)=>{})
    res.redirect('/') //Redirects to the main page
})

app.get('/readFiles/:id',checkAuth,(req,res)=>
    {
        if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")        
        const id = req.params.id
        fs.readdir(`./Folders/${id}`,function(err,files){
            res.render('index_updt',{files: files, id:id})
        })
        
})

app.post('/createFile/:id',checkAuth,(req,res)=>
    { 
        if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")
        const id = req.params.id
        //Writing a file into the directory which will be retrieved in the frontend aspect + req.body reason is because the title,description are under that HTML aspect
        fs.writeFile(`./Folders/${id}/${req.body.title.split(' ').join('')}.txt`,req.body.description,function(err){
            res.redirect(`/readFiles/${id}`) // As soon you as you click on the submit button, the route is redirected to primary
        })
    })

app.get('/fileView/:id/:fileName', checkAuth,(req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")
  const { id, fileName } = req.params
  fs.readFile(`./Folders/${id}/${fileName}`, 'utf8', (err, data) => {
    if (err) {console.error(err)
        return}
    res.render('show', { filename: fileName, data })
  });
});

app.get('/fileEdit/:id/:fileName',checkAuth, (req,res)=>{
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden")
    const {id,fileName} = req.params
    fs.readFile(`./Folders/${id}/${fileName}`,'utf-8',(err,data)=>{
        if(err){console.error(err) 
            return}
        res.render('edit',{filename:fileName,data,id})
    })
    
})

app.post('/updateFile/:id',checkAuth, (req,res)=>{
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden") // Simple Protection
    const {id} = req.params
    const fileName = req.body.title.split(' ').join('') + '.txt'
    fs.writeFile(`./Folders/${id}/${req.body.title.split(' ').join('')}.txt`,req.body.description,function(err){ res.redirect(`/fileView/${id}/${fileName}`)}
)
})


app.listen(3000)