from fastapi import FastAPI


def create_app():
    app = FastAPI()
    app.include_router(router)
    return app


app = create_app()
