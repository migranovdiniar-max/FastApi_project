from typing import Optional, List
from fastapi import FastAPI, Response, status, HTTPException, Depends
from fastapi.params import Body
import psycopg2
from psycopg2.extras import RealDictCursor
import time
from . import models, schemas, utils
from .database import engine, get_db
from sqlalchemy.orm import Session
from .routers import post, user

models.Base.metadata.create_all(bind=engine)

app = FastAPI()


while True:
    try:
        conn = psycopg2.connect(host='localhost',
                                database='fastapi',
                                user='postgres',
                                password='1234',
                                cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        print("DB connection is succesfull")
        break
    except Exception as error:
        print("Connecting to database failed")
        print("Error:", error)
        time.sleep(2)


my_posts = [{"title": "title of post 1",
             "content": "content of post 1",
             "id": 1}, {
                 "title": "favourite foods",
                 "content": "I like pizza",
                 "id": 2,
             }]


def find_post(id):
    for p in my_posts:
        if p["id"] == id:
            return p
        

def find_index_post(id):
    for i, p in enumerate(my_posts):
        if p['id'] == id:
            return i


app.include_router(post.router)
app.include_router(user.router)


@app.get("/")
def root():
    return {"message": "Hello, world"}