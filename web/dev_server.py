from app import app

if __name__ == '__main__':
    app.run(
        host=app.config['APP_HOST'],
        port=app.config['HOST_PORT'],
        debug=True
    )
