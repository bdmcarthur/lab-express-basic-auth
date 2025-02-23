'use strict';
const mongoose = require("mongoose");
const Schema   = mongoose.Schema;

const userSchema = new Schema({
    username: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        unique: true
      },
      passwordHash: {
        type: String,
        required: true
      },
      name: {
        type: String
      }
    
});

const User = mongoose.model("User", userSchema);

module.exports = User;
