@app.route('/importar_planilha', methods=['GET', 'POST'])
@login_required
def importar_planilha():
    if request.method == 'POST':
        file = request.files['planilha']
        if file and file.filename.endswith('.xlsx'):
            df = pd.read_excel(file)

            cobb_map = {
                '40°-59°': 1,
                '60°-79°': 2,
                '≥80°': 3
            }

            with sqlite3.connect(DB) as conn:
                for _, row in df.iterrows():
                    nome = row.get('Paciente')
                    nascimento = row.get('D.Nasc')
                    data_consulta = row.get('D.Atend')
                    grau = row.get('Grau')

                    if pd.isnull(nome) or pd.isnull(nascimento) or pd.isnull(data_consulta) or pd.isnull(grau):
                        continue  # Pula linhas incompletas

                    escore = cobb_map.get(grau.strip(), 0)
                    prioridade = 'Alta Prioridade' if escore > 2 else 'Prioridade Intermediária' if escore == 2 else 'Prioridade Eletiva'

                    cur = conn.cursor()
                    cur.execute("INSERT INTO pacientes (nome, nascimento) VALUES (?, ?)", (nome, nascimento))
                    paciente_id = cur.lastrowid

                    cur.execute("INSERT INTO consultas (paciente_id, data, escore, prioridade) VALUES (?, ?, ?, ?)",
                                (paciente_id, data_consulta, escore, prioridade))

            flash("Pacientes e consultas importados com sucesso.")
            return redirect(url_for('painel'))

    return render_template("importar.html")