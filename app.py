from Authentication import app, init_db

if __name__ == '__main__':
    init_db()            # create tables if needed
    app.run(debug=True)  # start the Flask dev server