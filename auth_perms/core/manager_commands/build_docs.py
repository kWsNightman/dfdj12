import os

from .docs_builder import build_docs_service
from .flow_builder import service_flows
from flask_script import Command, Option


class BuildDocs(Command):

    option_list = (
        Option('--path', '-p', dest='service_path', required=True),
        Option('--name', '-n', dest='service_name', required=True),
        Option('--file', '-f', dest='filename', default='README')
    )

    def run(self, service_path, service_name, filename='README'):
        service_path = os.path.abspath(service_path)
        service_flows(service_path, service_name, filename)
        build_docs_service(service_path, service_name)
