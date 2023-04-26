# PP-Stream

### What is this repository for?

* PP-Stream: Toward High-Performance Privacy-Preserving Neural Network
Inference via Distributed Stream Processing


### Dependencies

* c++17
* cmake (3.20.0)
* m4 (1.4.18)
* gmp (6.2.0)
* zeromq (4.2.2)
* boost (1.73+)
* [NumCpp](https://github.com/dpilger26/NumCpp.git)
* [AF-Stream](http://adslab.cse.cuhk.edu.hk/software/afstream/)

### How to run it?

Step 1: code preparation

* source code
	* ```modelprovider/afstream-0.2.0/apps/paillierworker/```
	* ```dataprovider/afstream-0.2.0/apps/paillierworker/```
	* ```dataprovider/SP```
* configuration files
	* ```modelprovider/afstream-0.2.0/conf/paillier_worker/paillier_worker.ini```
	* ```dataprovider/afstream-0.2.0/conf/paillier_worker/paillier_worker.ini```
* key files
	* ```publicdata/paillier_pub_key.txt```
	* ```publicdata/paillier_priv_key.txt```


Step 2: build and compile executable files  

```bash
cd modelprovider/afstream-0.2.0/apps/paillierworker
make

cd dataprovider/afstream-0.2.0/apps/paillierworker
make

cd dataprovider/SP
make
``` 


Step 3: execute

```bash
# In modelprovider/afstream-0.2.0/apps/paillierworker/:
# In terminal 1: 
./conv_cm_worker ../../conf/paillier_worker/paillier_worker.ini CONV_CM_Worker1 0

# In terminal 2:
./fc2_cm_worker ../../conf/paillier_worker/paillier_worker.ini FC2_CM_Worker1 0

# Interminal 3:
./fc3_cm_worker ../../conf/paillier_worker/paillier_worker.ini FC3_CM_Worker1 0

# In dataprovider/afstream-0.2.0/apps/paillierworker/:
# In terminal 4:
./relu_cm_worker ../../conf/paillier_worker/paillier_worker.ini ReLU_CM_Worker1 0

# In terminal 5:
./relu_merge_worker ../../conf/paillier_worker/paillier_worker.ini ReLU_Merge_Worker1 0

# In terminal 6:
./relu_cm_worker ../../conf/paillier_worker/paillier_worker.ini ReLU2_CM_Worker1 0

# In terminal 7:
./relu_merge_worker ../../conf/paillier_worker/paillier_worker.ini ReLU2_Merge_Worker1 0

# In terminal 8:
./fc3_merge_worker ../../conf/paillier_worker/paillier_worker.ini FC3_Merge_Worker1 0

In dataprovider/SP (send encrypted tensor to model provider):
# In terminal 9:
./service_provider1

```
