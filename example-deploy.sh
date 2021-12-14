#!/bin/bash
git clone [Git URL] /[temp_path]
cp -R /[temp_path]/* /[prod_path]/
rm -rf /[temp_path]/
chmod +rx /[prod_path]/run_*
