import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import plotly.express as px
import os
import sys

# Importa a classe DatabaseManager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from idsstarly import DatabaseManager

# Conexão com banco
db = DatabaseManager()

st.set_page_config(page_title="🔧 IDS Dashboard", layout="wide")
st.title("🔧 IDS Dashboard")

# Cria as abas
tab_grafico, tab_blacklist = st.tabs(["📊 Tráfego da Rede", "🚨 Blacklist"])


with tab_grafico:
    st.header("Tráfego de Rede")

    # Carrega os logs da tabela
    @st.cache_data
    def carregar_logs():
        db.cursor.execute("SELECT timestamp, src_ip, src_port, dst_ip, dst_port, label, descricao FROM logs")
        dados = db.cursor.fetchall()
        colunas = ["Timestamp", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port", "Label", "Descricao"]
        return pd.DataFrame(dados, columns=colunas)

    df = carregar_logs()

    if df.empty:
        st.warning("Nenhum dado de tráfego foi encontrado.")
        st.stop()

    st.write("Preview dos dados:", df.head())

    # Processa categorias
    contagem = df["Label"].value_counts()
    percent = (contagem / contagem.sum() * 100).round(1)

    resultado = pd.DataFrame({
        "Categoria": contagem.index,
        "Contagem": contagem.values,
        "Porcentagem (%)": percent.values
    })

    paleta = plt.get_cmap("tab20").colors[:len(resultado)]
    resultado["Cor"] = [f"background-color: {mcolors.to_hex(c)}" for c in paleta]

    col1, col2 = st.columns(2)
    with col1:
        fig, ax = plt.subplots()
        ax.pie(
            resultado["Contagem"],
            colors=paleta,
            startangle=90,
            explode=[0.1 if i == 0 else 0 for i in range(len(resultado))],
            pctdistance=0.8,
            labels=None
        )
        centro = plt.Circle((0, 0), 0.70, fc="white")
        fig.gca().add_artist(centro)
        ax.axis("equal")
        st.pyplot(fig, use_container_width=True)

    with col2:
     
        df_sem_cor = resultado.drop(columns=["Cor"])
        styled = df_sem_cor.style.apply(
            lambda _: [f"background-color: {mcolors.to_hex(c)}; color: black" for c in paleta],
            axis=0
        )
        st.dataframe(styled, use_container_width=True)

    # Top 10 IPs de origem
    st.subheader("📋 Top 10 IPs de Origem com Mais Pacotes")
    top_src = df["Src_IP"].value_counts().head(10).reset_index(name="contagem")
    top_src.columns = ["ip", "contagem"]

    fig = px.bar(
        top_src,
        x='contagem',
        y='ip',
        orientation='h',
        text='contagem',
        color='contagem',
        color_continuous_scale="Viridis",
        labels={'contagem': 'Pacotes', 'ip': 'IP de Origem'},
        title="Top 10 IPs por Pacotes Capturados"
    )

    fig.update_traces(texttemplate='%{text}', textposition='outside')
    fig.update_layout(
        yaxis={'categoryorder': 'total ascending'},
        plot_bgcolor='white',
        xaxis_title='Pacotes',
        yaxis_title='IP de Origem',
        margin=dict(l=100, r=20, t=50, b=50)
    )

    st.plotly_chart(fig, use_container_width=True)


with tab_blacklist:
    st.header("Lista Negra de IPs Suspeitos")

    @st.cache_data
    def carregar_blacklist():
        db.cursor.execute("SELECT ip, descricao, timestamp FROM blacklist")
        dados = db.cursor.fetchall()
        return pd.DataFrame(dados, columns=["IP", "INFO", "DATA"])

    bl = carregar_blacklist()

    if bl.empty:
        st.info("Nenhum IP consta na blacklist.")
    else:
        for _, row in bl.iterrows():
            with st.expander(f"IP: {row['IP']}"):
                st.write("**Informações:**", row["INFO"])
                st.write("**Data adicionado:**", row["DATA"])
