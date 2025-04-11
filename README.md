# Calectr — Caldera to VECTR Integration Tool

**Calectr** is a command-line tool that converts adversary simulation logs from [MITRE Caldera](https://github.com/mitre/caldera) into VECTR-compatible assessments. It transforms Caldera JSON logs into enriched CSVs using MITRE ATT&CK data and imports them into [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) via the GraphQL API.


##  What Can Calectr Do?

-  **Parse Caldera JSON logs** and convert them into VECTR-formatted CSVs
-  **Enrich MITRE techniques** with detection tips, URLs, and data sources
-  **Automatically upload test cases** as assessments, campaigns, and test cases to VECTR
-  Works with both **older and newer VECTR versions** (with or without Outcome Path support)
-  Also supports direct import of **VECTR-formatted CSVs**


##  Credits

> 💡 **Calectr is heavily inspired by the excellent work by [Security Risk Advisors](https://github.com/SecurityRiskAdvisors)** in their [`vectr-tools`](https://github.com/SecurityRiskAdvisors/vectr-tools) project.

I’ve extended their work to:
- Add Caldera-to-VECTR transformation
- Automatically enrich data using MITRE CTI
- Provide a seamless command-line workflow


##  Requirements

- Python 3.9+
- A running instance of VECTR with API key access
- Caldera JSON logs **or** VECTR-compatible CSVs
- Internet access (to fetch latest MITRE ATT&CK dataset)


##  Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/bhanunamikaze/calectr.git
   cd calectr
   ```

2. Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```


##  Configuration

### 1. Create a VECTR API Key

1. Log into your VECTR instance.
2. Click your profile in the top-right corner → **API Keys**.
3. Click **"Create API Key"**.
4. Copy the **Client ID** and **Secret** — format them as:
   ```
   API_KEY="CLIENT_ID:SECRET"
   ```

### 2. Create and configure your `.env` file

Create a `.env` file in the project root, and populate it like this:

```env
API_KEY="XPHN67C778OD5NGTARI0XW:cOUbbjVDgJ4av78JTeNUK3QVAVsKbau4lsXdISHqom4="
VECTR_GQL_URL="https://vectr.internal/sra-purpletools-rest/graphql"
TARGET_DB="MY_USER_DB"
ORG_NAME="Security Risk Advisors"
```

##  How to Export Caldera JSON Logs

1. **Login to your Caldera server**
2. Go to the **Operations** tab
3. Click on the operation you want to export
4. Click **Download Report** (top right corner)
5. In the dialog:
   - ✅ Check **"Include agent output"**
   - 📝 Select **"Event logs"**
6. Click **Download**

Save the downloaded `.json` file and use it as input to Calectr:

```bash
python main.py --caldera-json Files/operation_event-logs.json
```

##  Usage

### Option 1: From Caldera JSON logs

```bash
python main.py --caldera-json Files/operation_event-logs.json
```

This will:
1. Download the latest MITRE ATT&CK dataset
2. Convert the JSON logs to a VECTR-compatible CSV (`Files/vectr_mapped_output.csv`)
3. Upload the data to your VECTR instance using the API

---

### Option 2: From a VECTR-compatible CSV

```bash
python main.py --vectr-csv Files/vectr_mapped_output.csv
```

This will:
- Skip the MITRE and Caldera transformation steps
- Directly upload the CSV to your VECTR instance

---

##  Sample Commands

```bash
# Convert and import from Caldera JSON
python main.py --caldera-json Files/example-run.json

# Direct import from VECTR CSV
python main.py --vectr-csv Files/example-export.csv
```


##  License

This project is licensed under the MIT License.

> Portions adapted from [SecurityRiskAdvisors/vectr-tools](https://github.com/SecurityRiskAdvisors/vectr-tools).
