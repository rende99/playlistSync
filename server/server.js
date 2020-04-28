const express = require('express');
var bcrypt = require('bcrypt');
var SpotifyWebApi = require('spotify-web-api-node');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cors = require('cors')
const dotenv = require("dotenv");
const axios = require('axios');
const {uuid} = require('uuidv4');
const Cookies = require('js-cookie');
var cookieParser = require('cookie-parser');
var base64 = require('base-64');
const SC = require('soundcloud-v2-api');
var youtubeSearch = require('youtube-search');
const MongoClient = require('mongodb').MongoClient;
var ObjectId = require('mongodb').ObjectId;
var spotifyApi = new SpotifyWebApi({ clientId: String(process.env.spotifyClientID), clientSecret: String(process.env.spotifyClientSecret) });

const app = express();
const port = process.env.PORT || 5000;

dotenv.config();
process.env.TOKEN_SECRET;


const applePrivateKey = fs.readFileSync("AuthKey.p8").toString();
const youtubeDoc = require('../playlistsyncYoutube.json');
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json());
app.use(cookieParser())



function generateAccessToken(username, time) {
	// expires after an hour (3600 seconds = 60 minutes)
	return jwt.sign(username, process.env.TOKEN_SECRET, { expiresIn: time });
}
/*
function main() {
	youtubeSearch("asdf", {
		maxResults: 10,
		type: "video",
		key: youtubeDoc.api_key
	}, function(err, results){
		if(err){
			return console.log(err);
		}
		//tempSearchArray.push({data: results, source: "youtube"})
		console.dir(results);
	})
}
*/



MongoClient.connect('mongodb+srv://rende99:SkRxxW8QpLt2rLj@cluster0-gkxf8.gcp.mongodb.net/test?retryWrites=true&w=majority', { useUnifiedTopology: true })
.then(client => {
	const db = client.db('playlistDatabase')

	function authenticateToken(req, res, next) {
		// Gather the jwt access token from the request header
		const authHeader = req.headers['authorization']
		const token = authHeader && authHeader.split(' ')[1]
		console.log('token', token)
		if (token == null ){
			return res.sendStatus(401)
		}  // if there isn't any token
		
		jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
			console.log(err)
			if (err){
				return res.sendStatus(401)
			}
			req.user = user
			next() // pass the execution off to whatever request the client intended
		})
	}

	app.listen(port, () => console.log(`Listening on port ${port}`));

	const appleJWT = jwt.sign({}, applePrivateKey, {
		algorithm: "ES256",
		expiresIn: "180d",
		issuer: process.env.appleTeamId,
		header: {
		  alg: "ES256",
		  kid: process.env.appleKeyId
		}
	});
	console.log("apple", appleJWT)
	/*
	spotifyApi.clientCredentialsGrant().then(function (data) {
		// Save the access token so that it's used in future calls
		spotifyApi.setAccessToken(data.body['access_token']);
		console.log("Spotify access token received")
	}, function (err) {
		console.log('Something went wrong when retrieving an access token', err.message);
	});

	*/
	SC.init({
		clientId: process.env.soundcloudID,
		cors: true
	})

	app.get('/token', function (req, res) {
		res.send( {token: appleJWT} );
	});


	app.get('/playlists', (req, res) => {
		authenticateToken(req, res, function(){
			db.collection('users').findOne({user: req.user.username}).then(results => {
				res.send({ data: results })
			})
		})
	})

	app.get('/getAllSongs/:playlistName', (req, res) => {
		console.log("params", req.params.playlistName)
		authenticateToken(req, res, async function(){
			console.log("info here", req.user.username, req.params.playlistName)
			await db.collection('users').find(
				{
					"user": req.user.username,
					"playlists.name": req.params.playlistName
				},
			).project({"playlists.$": 1}).toArray()
			.then(async results => {
				//GET SONGS FROM API HERE!
				var temp = []
				for(let i = 0; i < results[0].playlists[0].songs.length; i++){

					temp.push({
						title: results[0].playlists[0].songs[i].title,
						artist: results[0].playlists[0].songs[i].artist,
						image: results[0].playlists[0].songs[i].image,
						id: results[0].playlists[0].songs[i].songID,
						source: results[0].playlists[0].songs[i].service,
						dbID: results[0].playlists[0].songs[i].dbID
					})
					
				}
				console.log("temp rIGHT BEFORE:", temp)

				res.send({data: temp});
			}).catch(function(err){
				console.log(err);
				res.send( {status: false} );
			})
		})
	})

	app.get('/search/:query-:useSpotify-:useApple-:useSoundcloud-:useYoutube', (req, res) => {
		console.log(req.headers.authorization);
		var useSpotify = (req.params.useSpotify == 'true')
		var useApple = (req.params.useApple == 'true')
		var useSoundcloud = (req.params.useSoundcloud == 'true')
		var useYoutube = (req.params.useYoutube == 'true')

		console.log("before numperservice")
		//number of results to find:
		var numResults = 10;
		var numPerService = Math.floor(numResults/[useSpotify,useApple,useSoundcloud,useYoutube].filter(v => v).length)

		console.log("numperservice", numPerService)
		//console.log("BOOLEANS:", useSpotify,useApple,useSoundcloud);
		var tempSearchArray = []
		console.log("Cookie: ", req.cookies)
		authenticateToken(req, res, async function(){
			if (useSpotify) {
				await axios.get('https://api.spotify.com/v1/search?q=' + encodeURIComponent(req.params.query) + '&type=track&limit=' + numPerService,{
					headers: {
						'Authorization': 'Bearer ' + req.cookies.spotifyToken
					}
				})
				.then(function (data) {
					// Send the first (only) track object
					console.log(data)
					for(var i = 0; i < data.data.tracks.items.length; i++){
						tempSearchArray.push({data: data.data.tracks.items[i], source: "spotify"})
					}

					//console.log("data body track items", data.body.tracks.items)

				}, function (err) {
					console.error(err);
				});
			}
			if (useApple) {
				await axios.get('https://api.music.apple.com/v1/catalog/US/search?term=' + encodeURI(req.params.query) + '&limit=' + numPerService, {
					headers: {
						'Authorization': 'Bearer ' + appleJWT
					}
				})
				.then(response => {
					for(var i = 0; i < response.data.results.songs.data.length; i++){
						console.log("apple response", response.data.results.songs.data[i]);

						tempSearchArray.push({data: response.data.results.songs.data[i], source: "apple"})
					}
				}).catch(err => {
					console.error(err)
				});
			}
			if(useSoundcloud) {
				await SC.get('/search/tracks', {
					q: req.params.query, 
					limit: numPerService
				}).then(response => {
					console.log("results from soundcloud:", response.collection[0]);
					for(var i = 0; i < response.collection.length; i++){
						//console.log("soundcloud response", response.collection[i]);
						tempSearchArray.push({data: response.collection[i], source: "soundcloud"})
					}
				}).catch(err => {
					console.error(err);
				})
			}
			if(useYoutube) {
				var opts = {
					maxResults: numPerService,
					type: "video",
					key: youtubeDoc.api_key
				}
				var results = await youtubeSearch(req.params.query, opts).catch(function(err){console.error(err)})
				console.log(results.results)
				for(var i = 0; i < results.results.length; i++){
					tempSearchArray.push({ data: results.results[i], source: "youtube"});
				}
				
			}
			console.log("tsearcharray", tempSearchArray)
			res.send({data: tempSearchArray});
		})
	})

	app.get('/playSong/:deviceID-:songToPlay', (req, res) => {
		var songToPlay = JSON.parse(req.params.songToPlay);
		var deviceID = req.params.deviceID;
		var tempToken
		authenticateToken(req, res, async function(){
			switch(songToPlay.source){
				case 'spotify':
					if(!req.cookies.spotifyToken){
						// we need to get a new token
						if(!req.cookies.spotifyRefresh){
							// we don't have a refresh token, either!
							console.log("start it all over again!")
							res.redirect('https://accounts.spotify.com/authorize?client_id='+process.env.spotifyClientID+'&response_type=code&redirect_uri=' + 
							encodeURIComponent('http://localhost:3000/auth/spotify') + '&scope=user-modify-playback-state%20user-read-playback-state%20user-read-currently-playing');
						}else{
							console.log("spotify token does not exist")
							await axios.post('https://accounts.spotify.com/api/token?grant_type=refresh_token&refresh_token=' + req.cookies.spotifyRefresh, null, {
								headers: {
									'Authorization': 'Basic ' + base64.encode(process.env.spotifyClientID + ':' + process.env.spotifyClientSecret)
								}
							}).then(response => {
								tempToken = response.data.access_token
							})
						}

					}
					console.log(req.cookies.spotifyToken)
					await axios.put('https://api.spotify.com/v1/me/player/play?device_id='+deviceID , 
					{
						'uris': ['spotify:track:' + String(songToPlay.id)]	
					}, {
						headers: {
							'Authorization': 'Bearer ' + (tempToken ? tempToken : req.cookies.spotifyToken)
						}
						
					}).then(result => {
						res.send( {status: true, token: tempToken} )
					}).catch(err => {
						console.log(err)
						res.send( {status: false, token: tempToken} )
					})
					console.log("SPOTIFY");	

					break;
				case 'apple':
				
					break;
				default:
					break;

			}
		})
	})

	app.post('/transferState', (req,res) => {
		authenticateToken(req, res, async function(){
			var newDeviceID = req.body.newDeviceID;
			var currentSong = req.body.currentSong;
			await axios.put('https://api.spotify.com/v1/me/player', {
				'device_ids': [newDeviceID]
			}, {
				headers: {
					'Authorization': 'Bearer ' + req.cookies.spotifyToken
				}
			})
		})
	})

	app.get('/pauseSong/:songToPause', (req, res) => {
		var songToPause = JSON.parse(req.params.songToPause);
		authenticateToken(req, res, async function(){
			switch(songToPause.source){
				case 'spotify':
					//check if spotify token exists
					if(req.cookies.spotifyToken){
						await axios.put('https://api.spotify.com/v1/me/player/pause', 
						null, {
		
							headers: {
								'Authorization': 'Bearer ' + req.cookies.spotifyToken
							}
							
						}).then(result => {
							res.send( {status: true} )
						}).catch(err => {
							console.log(err.response.data)
							res.send( {status: false} )
						})
					}else{
						console.log("spotify token no exist noooo")
					}
					
					break;
				default:
					break;
			}
			res.send( {status: false} )
		})
	});

	app.get('/devices', (req, res) => {
		//https://api.spotify.com/v1/me/player/devices
		console.log("getting devices")
		authenticateToken(req, res, async function(){
			await axios.get('https://api.spotify.com/v1/me/player/devices',
			{

				headers: {
					'Authorization': 'Bearer ' + req.cookies.spotifyToken
				}
				
			}).then(result => {
				console.log("device res:", result.data)
				res.send( {data: result.data} )
			}).catch(err => {
				console.log(err.response.data)
				res.send( {data: null} )
			})
		})
	})

	app.post('/newplaylist', (req, res) => {
		authenticateToken(req, res, async function(){
			//username is held in req.user.username
			//console.log(req)
			var doc = await db.collection('users').updateOne({"user": req.user.username}, {
				$push: {playlists: {name: req.body.playlistName, songs: []}}
			}).catch(function(err){
				console.log(err);
				res.send( {status: false} );
			})
			res.send( {status: true} );
			
			
		})
	})

	app.post('/addSong', (req, res) => {
		authenticateToken(req, res, async function(){
			//username is held in req.user.username
			console.log("about to try and add")
			var doc = await db.collection('users').updateOne({"user": req.user.username, "playlists.name": req.body.playlistName }, {
				$push: {"playlists.$.songs": {
					title: req.body.title,
					artist: req.body.artist,
					image: req.body.image,
					songID: req.body.id,
					service: req.body.source,
					dbID: uuid()
				}}
			}).catch(function(err){
				console.log(err);
				res.send( {status: false} );
			})
			res.send( {status: true} );
		})
	})

	app.post('/changeOrder', (req,res) => {
		authenticateToken(req, res, async function(){
			console.log("about to try and change order")
			var startingIndex = req.body.startingIndex;
			var endingIndex = req.body.endingIndex;
			console.log("movingItem: ", req.body.movingItem);
			//remove old index at position first
			await db.collection('users').updateOne({"user": req.user.username, "playlists.name": req.body.playlistName }, {
				$unset : {
					["playlists.$.songs." + startingIndex]: null 
				}	
			})
			await db.collection('users').updateOne({"user": req.user.username, "playlists.name": req.body.playlistName }, {
				$pull : {
					["playlists.$.songs"]: null
				}	
			})

			//update new document
			var doc = await db.collection('users').updateOne({"user": req.user.username, "playlists.name": req.body.playlistName }, {
				$push: {
					"playlists.$.songs": {
						$each: [{
							'title': req.body.movingItem.title,
							'artist': req.body.movingItem.artist,
							'image': req.body.movingItem.image,
							'songID': req.body.movingItem.id,
							'service': req.body.movingItem.source,
							'dbID': req.body.movingItem.dbID
						}],
						$position: endingIndex
					}
				}
			}).catch(function(err){
				console.log(err);
				res.send( {status: false} );
			})
			
			res.send( {status: true} );
		})
	})



	//LOGIN METHODS -------------------------------------------------------------------------------------------------------------------------

	app.get('/spotifyLogin', async (req,res) => {
		console.log("beginning attempt to login to spotify");
		authenticateToken(req, res, async function(){
			res.setHeader("Content-Type", "text/html")
			res.redirect('https://accounts.spotify.com/authorize?client_id='+process.env.spotifyClientID+'&response_type=code&redirect_uri=' + encodeURIComponent('http://localhost:3000/auth/spotify') +
			'&scope=user-modify-playback-state%20user-read-playback-state%20user-read-currently-playing');
		})
	})
	app.get('/appleLogin', async (req,res) => {
		console.log("beginning attempt to login to apple");
		authenticateToken(req, res, async function(){
			res.setHeader("Content-Type", "text/html")
			res.redirect('https://idmsa.apple.com/IDMSWebAuth/auth?oauth_token='+applePrivateKey)
		})
	})

	app.get('/spotifyCallback/:code', (req,res) => {
		console.log("callback after logging into spotify", base64.encode(process.env.spotifyClientID + ':' + process.env.spotifyClientSecret));
		var code = req.params.code
		console.log(code)
		authenticateToken(req, res, async function(){
			console.log("token authenticated", code)
			await axios.post('https://accounts.spotify.com/api/token?grant_type=authorization_code&code='+code+'&redirect_uri='+encodeURIComponent('http://localhost:3000/auth/spotify') + 
			'&client_id='+process.env.spotifyClientID + '&client_secret='+process.env.spotifyClientSecret, null, {
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					"Access-Control-Allow-Origin": "*",
				}
			}).then(response => {
				console.log("the response from spotify",response.data)
				res.send({data: response.data})
			}).catch(ex => {
				console.error("error:", ex)
			});
		})

	})

	app.get('/signin/:user-:pass', async (req, res) => {
		console.log("GETTTTT")
		var doc = await db.collection('users').findOne({
			"user": req.params.user
		}).catch(function () {
			res.send({ status: false })
		})
		console.log("doc", doc);
		if (doc) {
			bcrypt.compare(req.params.pass, doc.pass, function (err, result) {
				console.log(result)
				if (result && req.params.user == doc.user) {
					// correct admin info given
					const token = generateAccessToken({ username: req.params.user }, '2592000s');
					/*
					db.collection('users').updateOne({user: req.params.user}, {
						$set: {refresh: refreshToken}
					})
					*/
					res.send({ status: true, jwt: token });
				} else {
					//something was wrong
					res.send({ status: false });
				}
			});
		} else {
			res.send({ status: false })
		}
	});

	app.post('/createAccount', async (req, res) => {
		var saltRounds = 10;
		var docExists = await db.collection('users').find({
			"user": req.body.user
		}).count() > 0

		if (docExists || req.body.pass.length < 8) {
			console.log("user already exists or password sucks")
			res.send({ status: false })
			return;
		}
		//doc should be null (we can't have two users with the same username)
		await bcrypt.hash(req.body.pass, saltRounds, async function (err, hash) {
			const token = generateAccessToken({ username: req.body.user }, '2592000s');
			
			await db.collection('users').insertOne({
				user: req.body.user,
				pass: hash,
				playlists: []
			}).catch(function (err) {
				console.log(err)
			});

			res.send({ status: true, jwt: token })
		});
	})

}).catch(error => console.error(error))

exports.cryptPassword = function (password, callback) {
	bcrypt.genSalt(10, function (err, salt) {
		if (err)
			return callback(err);

		bcrypt.hash(password, salt, function (err, hash) {
			return callback(err, hash);
		});
	});
};

exports.comparePassword = function (plainPass, hashword, callback) {
	bcrypt.compare(plainPass, hashword, function (err, isPasswordMatch) {
		return err == null ?
			callback(null, isPasswordMatch) :
			callback(err);
	});
};

