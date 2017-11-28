# Jail Sessions

## Objective
Extend an app that leverages [https://www.npmjs.com/package/client-sessions](client-sessions) to create **sessions** for users to log in. Use those **sessions** with **middleware** to protect certain routes in the app.


### Part I - Setup
- Copy the jail starter code into your own project folder and install dependencies
- You've been provided with a database dump of the users you will need for this application. Start mongod, then add these users to your database with `mongorestore -d jail dump/jail`
- You can use RoboMongo to verify that you successfully imported the data.


### Part II - Lockdown
- Not everyone in the jail can go everywhere. To limit access, write several middleware functions and **mount** them to the appropriate routes to make sure only the appropriate users can access certain rooms of the jail.
- Write some more middleware that enforces the following rules:
    * Alice (warden) can go anywhere.
    * Bob (guard) can go anywhere, except the warden's office.
    * Carlos (visitor) can go to the lobby and the visitor's lounge.
    * Eve (prisoner) can go to the cafeteria or Eve's jail cell.
    * Mallory (prisoner) can go to the cafeteria or Mallory's cell.
