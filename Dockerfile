FROM ubuntu:18.04

RUN apt-get update -y && \
    apt-get install -y python3.8 python3.8-dev python3.8-distutils python3.8-venv && \
    apt-get install -y python3-pip && \
    python3.8 -m pip install --upgrade pip && \
    python3.8 -m pip install grpcio-tools==1.35.0

# We copy just the requirements.txt first to leverage Docker cache
COPY src/requirements.txt /Controller/src/requirements.txt

WORKDIR /Controller/src/

RUN python3.8 -m pip install -r requirements.txt

SHELL ["/bin/bash", "-c"]
COPY src/main_setup_docker.py /Controller/src/
COPY src/main_grpc.py /Controller/src/
COPY src/load.py /Controller/src/
COPY src/entrypoint.sh /Controller/src/
COPY src/bfruntime.proto /Controller/src/
COPY src/bfruntime_pb2.py /Controller/src/
COPY src/bfruntime_pb2_grpc.py /Controller/src/
COPY src/client.py /Controller/src/
COPY src/info_parse.py /Controller/src/
COPY src/bfrt_client.py /Controller/src/
COPY src/p4info.yaml /Controller/src/
#COPY ../protos/nbn.proto /Controller/src/
COPY src/nbn_pb2.py /Controller/src/
COPY src/nbn_pb2_grpc.py /Controller/src/
#COPY ../protos/mac.proto /Controller/src/
COPY src/mac_pb2.py /Controller/src/
COPY src/mac_pb2_grpc.py /Controller/src/
COPY src/run-codegen.py /Controller/src
COPY src/controller.log /Controller/src
COPY src/controller_config.yaml /Controller/src
COPY src/tna_binary.bin /Controller/src

WORKDIR tna_nbnswitch
COPY src/tna_nbnswitch/bf-rt.json /Controller/src/tna_nbnswitch
WORKDIR pipe
COPY src/tna_nbnswitch/pipe/context.json /Controller/src/tna_nbnswitch/pipe
COPY src/tna_nbnswitch/pipe/tofino.bin /Controller/src/tna_nbnswitch/pipe
WORKDIR /Controller/src/

#RUN python3.8 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. bfruntime.proto
#RUN python3.8 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. mac.proto
#RUN python3.8 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. nbn.proto

ENV VENV /Controller/venv

RUN chmod +x /Controller/src/entrypoint.sh

ENTRYPOINT ["/Controller/src/entrypoint.sh"]