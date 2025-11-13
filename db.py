import sqlite3
import os, sys
from typing import Tuple, List, Optional
from typing import Dict

# TODO Secure password db 

class DataBase:
    """Database management class (SQLite3) """

    def __init__(self) -> None:
        DB_PATH = self._get_db_path()
        self.connection = self._connect(DB_PATH)

        self._create_table()


    def add_resource(self, *, name: str, login: str = '', mail: str = '', note: str = '', passwd: str) -> None:
        query = "INSERT INTO resources (name, login, mail, note, password) VALUES (?, ?, ?, ?, ?)"
        self._execute(query, (name, login, mail, note, passwd))

    def update_resource(self, name: str, *, new_name: str | None = None, 
                        login: str | None = None, mail: str | None = None, 
                        note: str | None = None, passwd: str | None = None ) -> None:
        data = {'name': new_name, 'login': login ,
                'mail': mail, 'note': note, 'password': passwd}
        filtered_data = {k: v for k, v in data.items() if v}

        qq = ', '.join([f"{k} = ?" for k in filtered_data.keys()])
        query = f"UPDATE resources SET {qq} WHERE name = ?"
        self._execute(query, (*list(filtered_data.values()), name))


    def get_resources(self) -> List:
        query = "SELECT name FROM resources"
        res = self._execute(query).fetchall()
        resources = [row[0] for row in res]
        return resources

    def get_resource_info(self, resource: str) -> Dict:
        query = "SELECT * FROM resources WHERE name = ?"
        res = dict(self._execute(query, (resource, )).fetchone())
        return res

    def delete_resource(self, id: int) -> None:
        query = "DELETE FROM resources WHERE id = ?"
        self._execute(query, (id, ))

    def _get_db_path(self):
        if getattr(sys, 'frozen', False):  # Running as a PyInstaller EXE
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, ".batadase.db")

        

    def _connect(self, dbname: str) -> sqlite3.Connection:
        """Connecting to the DB"""
        connection = sqlite3.connect(dbname)
        connection.row_factory = sqlite3.Row
        return connection


    def _create_table(self) -> None:
        self._execute('''
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                login TEXT,
                mail TEXT,
                note TEXT,
                password TEXT 
            )
        ''')

    def _close(self) -> None:
        """Close connection"""
        if self.connection:
            self.connection.close()
    
    def _execute(self, query: str, params: Tuple = ()) -> sqlite3.Cursor:
        """Execute query"""
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        cursor.connection.commit()
        return cursor

    def __del__(self):
        self._close()
