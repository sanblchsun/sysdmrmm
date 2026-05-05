### Команда запуска dev-окружения:

docker compose -f docker-compose.dev.yml up -d --build
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
alembic revision --autogenerate -m "1"
alembic upgrade head
python create_admin.py
kill -9 $(lsof -t -i:8000)
uvicorn app.main:app --host 0.0.0.0 --port 8000
docker




### Проект только для примера, не удачный
