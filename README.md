# Altitude Air
It is a task for creating the registration page as per the assignment

### Step-1
Clone the repository and open in VS code.
 - `git clone git@github.com:code77withHimanshu/altitude_air.git`

Note: In order to access the `altitude_air_users.sql` file, import it in MySql Workbench. Then use the database `altitude_air` to see all the tables.

### Step-2
Go to the backend folder and open .env file.
You can change the .env file according to your configuration.
Note: If you are using mysql port 3306(default port) then change the following .env file accordingly.

server/.env
```markdown
DB_HOST=127.0.0.1
DB_PORT=3307
DB_USER=root
DB_PASSWORD=tiger
DB_NAME=altitude_air
PORT=5000
JWT_SECRET="Cron!#@$afxw"
```


### Step-3
Open the terminal and write the following commands

- `cd .\server\`
- `npm install`
- `node index.js`

This will run the server on the local and you will see Connected to MySQL database.


### Step-4
Open another terminal and write the following commands

- `cd .\client\`
- `npm install`
- `npm start`

This will start the frontend on the local



### Step-5
Go to Register to create your own user or Go to Sign In and access the dummy user i.e. 


username: raj@sh
Password: 123


username: joe@rg123
Password: 123



I have used `MySQL` for storing data. 

BackEnd Development with `Express.js`. 

Server-Side Logic with `Node.js`.

Frontend Development with `React.js`.
