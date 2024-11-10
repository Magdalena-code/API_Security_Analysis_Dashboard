*Set up*
	
Download the front- and backend from GitHub (https://github.com/Magdalena-code/API_Security_Analysis_Dashboard)

Start both in appopriate IDEs

Set up the virtual enviroment for the Python backend and import the necessary packages

Also install:

- pip install python-dotenv

- pip install openpyxl
  
- the package flask-cors may needs to be installed manually depending on the IDE

Adjust the .env files regarding paths

Start the docker „master-postgres“

- docker pull magdalenacode/masterthesis:latest
  
- docker run --name master-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d magdalenacode/masterthesis:latest

Run the python-script „Create_Tables.py“

Run the start_services.bat

Check the logs if an issue occurs

Open http://localhost:5173/ 

Open http://localhost:5000/apidocs for the API documentation

To test the application run the python-script „Insert_Script_Dummy.py“
