import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from idsstarly import *
st.title("Gráfico de Rede")


db = DatabaseManager()

def carregar_dados_agrupados():
    db.cursor.execute("SELECT label, COUNT(*) FROM logs GROUP BY label")
    dados = db.cursor.fetchall()
    df = pd.DataFrame(dados, columns=['Label', 'Quantidade'])
    return df


df = carregar_dados_agrupados()
print(df.head(10))
# Passo 2: Agrupando dados
col_categoria = df.columns[0] 
contagem = df.set_index('Label')['Quantidade']
st.table(contagem.rename_axis("Categoria").reset_index(name="Contagem"))

            # Passo 3: Montando gráfico
                # Design
sizes = contagem.values
texto = contagem.index
percent = (contagem/ contagem.sum()*100).round(1)
expandir = [0.1 if i == 0 else 0 for i in range(len(texto))]
# Inserindo os dados para tebela
resultado = pd.DataFrame({
'Categoria': texto,
'Contagem': sizes,
'Porcentagem (%)': percent.round(2)
})
# Gerando as cores
cor = plt.get_cmap('tab20').colors[:len(texto)]
resultado['cor'] = [f'background-color: {matplotlib.colors.to_hex(c)}' for c in cor]

# Colunas
col1, col2 = st.columns([1,1])

with col1:
    fig, ax = plt.subplots()

    wedges, texts = ax.pie(sizes,
    labels=None,
    startangle=90,
    colors=cor,
    pctdistance=0.8,
    explode = expandir)


    # pizza anel
    centro_circulo = plt.Circle((0,0), 0.70, fc = 'white')
    fig.gca().add_artist(centro_circulo)
    ax.axis("equal")


    # Passo 4: Imprimindo gráfico na tela
    st.pyplot(fig)

# Passo 5: Tabela do grafico
with col2:
    # Cores na tabela 
  
    resultado = resultado.drop(columns=["cor"])
    #resultado = resultado.drop(columns=["Label"])
    styled = resultado.style.apply(
        
        lambda _: [f'background-color: {matplotlib.colors.to_hex(c)}; color: black' for c in cor],
        axis=0
       
    )
    
    st.dataframe(styled, use_container_width=True, height=400)

    # Legenda visual
    legenda = ""
    for cor, cat in zip (cor, texto):
        hexc = matplotlib.colors.to_hex(cor)
        legenda +=(
            f"<div style='display:inline-block;"
            f"width:15px; height:15px; background:{hexc};"
            f"margin-right:5px;'></div>{cat}&nbsp;&nbsp;"
        )
        #st.markdown(legenda, unsafe_allow_html=True)