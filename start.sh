echo "creating virtual environment"
python3 -m venv venv

echo "activating virtual environment"
source venv/bin/activate

echo "installing requirements"
pip install -r requirements.txt

echo "starting the application"
python app.py

echo "application started"