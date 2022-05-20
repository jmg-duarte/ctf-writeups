const socket = require("socket.io-client")("https://woooosh.2020.chall.actf.co/");

socket.on('shapes', shapes => {
    socket.emit("click", shapes[0].x, shapes[0].y);
});

socket.on('disp', disp => {
    console.log(disp);
});

socket.on('score', score => {
    console.log(score);
});

socket.emit("start");