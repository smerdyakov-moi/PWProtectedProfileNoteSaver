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

// ✅ Secure editProfile
app.get('/editProfile/:id', checkAuth, async (req, res) => {
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden");

    let user = await userModel.findOne({ _id: req.params.id });
    res.render('UpdatePage', { user });
});

// ✅ Secure update
app.post('/update/:userid', checkAuth, async (req, res) => {
    if (req.user.id !== req.params.userid) return res.status(403).send("Forbidden");

    let { username, email, image } = req.body;
    await userModel.findOneAndUpdate({ _id: req.params.userid }, { username, image }, { new: true });
    res.redirect('/userSitePage');
});

// ✅ Secure delete
app.get('/deleteProfile/:ID', checkAuth, async (req, res) => {
    if (req.user.id !== req.params.ID) return res.status(403).send("Forbidden");

    let deletedUser = await userModel.findOneAndDelete({ _id: req.params.ID });
    res.cookie("token", "");
    fs.rmdir(`./Folders/${req.params.ID}`, { recursive: true }, (err) => {});
    res.redirect('/');
});

// ✅ Secure file read
app.get('/readFiles/:id', checkAuth, (req, res) => {
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden");

    const id = req.params.id;
    fs.readdir(`./Folders/${id}`, function (err, files) {
        res.render('index_updt', { files: files, id: id });
    });
});

// ✅ Secure file create
app.post('/createFile/:id', checkAuth, (req, res) => {
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden");

    const id = req.params.id;
    fs.writeFile(`./Folders/${id}/${req.body.title.split(' ').join('')}.txt`, req.body.description, function (err) {
        res.redirect(`/readFiles/${id}`);
    });
});

// ✅ Secure file view
app.get('/fileView/:id/:fileName', checkAuth, (req, res) => {
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden");

    const { id, fileName } = req.params;
    fs.readFile(`./Folders/${id}/${fileName}`, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return;
        }
        res.render('show', { filename: fileName, data });
    });
});

// ✅ Secure file edit
app.get('/fileEdit/:id/:fileName', checkAuth, (req, res) => {
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden");

    const { id, fileName } = req.params;
    fs.readFile(`./Folders/${id}/${fileName}`, 'utf-8', (err, data) => {
        if (err) {
            console.error(err);
            return;
        }
        res.render('edit', { filename: fileName, data, id });
    });
});

// ✅ Secure file update
app.post('/updateFile/:id', checkAuth, (req, res) => {
    if (req.user.id !== req.params.id) return res.status(403).send("Forbidden");

    const { id } = req.params;
    const fileName = req.body.title.split(' ').join('') + '.txt';
    fs.writeFile(`./Folders/${id}/${fileName}`, req.body.description, function (err) {
        res.redirect(`/fileView/${id}/${fileName}`);
    });
});


app.listen(3000)