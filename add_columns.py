import sqlite3


def add_columns():
    conn = sqlite3.connect('fila_escoliose.db')
    cursor = conn.cursor()

    try:
        # Adicionar coluna tipo_escoliose se não existir
        cursor.execute("""
            SELECT COUNT(*) FROM pragma_table_info('consultas') 
            WHERE name='tipo_escoliose'
        """)
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE consultas 
                ADD COLUMN tipo_escoliose TEXT
            """)
            print("Coluna tipo_escoliose adicionada com sucesso!")

        # Adicionar coluna grau_curva se não existir
        cursor.execute("""
            SELECT COUNT(*) FROM pragma_table_info('consultas') 
            WHERE name='grau_curva'
        """)
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE consultas 
                ADD COLUMN grau_curva TEXT
            """)
            print("Coluna grau_curva adicionada com sucesso!")

        # Adicionar coluna observacoes se não existir
        cursor.execute("""
            SELECT COUNT(*) FROM pragma_table_info('consultas') 
            WHERE name='observacoes'
        """)
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE consultas 
                ADD COLUMN observacoes TEXT
            """)
            print("Coluna observacoes adicionada com sucesso!")

        conn.commit()
        print("Alterações concluídas com sucesso!")

    except Exception as e:
        print(f"Erro ao adicionar colunas: {str(e)}")
        conn.rollback()

    finally:
        conn.close()


if __name__ == "__main__":
    add_columns()
