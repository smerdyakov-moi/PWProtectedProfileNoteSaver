const mongoose = require('mongoose')
mongoose.connect('mongodb://127.0.0.1:27017/LearningAuth')

const userSchema = mongoose.Schema({
    username: String,
    email: String,
    password: String,
    age: Number,
    image: String
})

module.exports = mongoose.model('user',userSchema)
