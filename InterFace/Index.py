import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import os
import plotly.express as px

st.title("🔧 IDS Dashboard")

# Caminho da pasta de dados
folder_path = os.path.abspath("Dados")
if not os.path.exists(folder_path):
    st.error("A pasta 'Dados' não existe.")
    st.stop()

csv_files = [f for f in os.listdir(folder_path) if f.endswith('.csv')]

# Cria duas abas
tab_grafico, tab_blacklist = st.tabs(["📊 Trafego da Rede", "🚨 Blacklist"])

with tab_grafico:
    st.header("Tráfego de Rede")

    # Filtra apenas os CSVs de tráfego (exclui blacklist.csv)
    traffic_files = [f for f in csv_files if f.lower() != "blacklist.csv"]

    if not traffic_files:
        st.warning("Não há arquivos de tráfego na pasta.")
        st.stop()

    selected_traffic = st.selectbox("Selecione o CSV de tráfego", traffic_files)
    file_path = os.path.join(folder_path, selected_traffic)

    # Lê com fallback de encoding
    try:
        df = pd.read_csv(file_path, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, encoding="latin1")

    st.write("Preview:", df.head())

    # Valida que há colunas suficientes
    if len(df.columns) < 7:
        st.error(f"O arquivo selecionado tem apenas {len(df.columns)} colunas e não parece ser de tráfego.")
        st.stop()

    # Extrai a coluna de categoria (coluna 6)
    col_categoria = df.columns[6]
    contagem = df[col_categoria].value_counts()
    percent = (contagem / contagem.sum() * 100).round(1)

    # Prepara DataFrame de resultados
    resultado = pd.DataFrame({
        "Categoria": contagem.index,
        "Contagem": contagem.values,
        "Porcentagem (%)": percent.values
    })

    # Gera cores e CSS
    paleta = plt.get_cmap("tab20").colors[:len(resultado)]
    resultado["Cor"] = [
        f"background-color: {mcolors.to_hex(c)}" for c in paleta
    ]

    # Layout lado a lado
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
        centre = plt.Circle((0, 0), 0.70, fc="white")
        fig.gca().add_artist(centre)
        ax.axis("equal")
        st.pyplot(fig, use_container_width=True)

    with col2:
        styled = (
            resultado.style
                     .apply(lambda _: resultado["Cor"], axis=0)
        )
        # Esconde a coluna auxiliar 'Cor'
        st.dataframe(
            styled,
            use_container_width=True,
            column_config={"Cor": None}
        )

    #plotando os TOP 10 principais ips
    st.subheader("📋 IP de Origem com mais Pacotes")
    src_contagem = (df["Src_IP"].value_counts().head(10).reset_index(name="contagem")
                    .rename(columns={"index": "ip"}))
    src_contagem.columns = ['ip', 'contagem']

    #criando o grafico(isso aqui é muita doidera....)
    fig = px.bar(
        src_contagem,
        x = 'contagem',
        y = 'ip',
        orientation='h',
        text= "contagem",
        color='contagem',
        color_continuous_scale="Viridis",
        labels={'contagem': 'Pacotes', 'ip': 'IP de Origem'},
        title="Top 10 IPs por Pacotes Capturados")
    
    fig.update_traces(texttemplate='%{text}', textposition='outside')
    fig.update_layout(
        yaxis={'categoryorder':'total ascending'},
        plot_bgcolor='white',
        xaxis_title='Pacotes',
        yaxis_title='IP de Origem',
        margin=dict(l=100, r=20, t=50, b=50),)
    st.plotly_chart(fig, use_container_width=True, theme='streamlit')

   




with tab_blacklist:
    st.header("Lista Negra de IPs Suspeitos")
    #Tou usando esse doc apenas para teste
    blacklist_path = os.path.join(folder_path, "blacklist.csv")
    if os.path.exists(blacklist_path):
        #Ajustando os ip´s banidos'
        bl = pd.read_csv(blacklist_path)
        for _, row in bl.iterrows():
            with st.expander(f"IP: {row['IP']}"):
                st.write("**Informações:**", row["INFO"])
                st.write("**Data adcionado:**", row["DATA"])
    else:
        st.info("Crie um arquivo 'blacklist.csv' na pasta Dados com colunas 'ip' e 'info'.")
