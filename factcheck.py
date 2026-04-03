import requests

API_KEY = "AIzaSyBw2pBlU1zOvZOTz27MhcSe-4FuFe36BGM"

def check_fact_google(query: str):
    url = "https://factchecktools.googleapis.com/v1alpha1/claims:search"

    params = {
        "query": query,
        "key": API_KEY
    }

    try:
        res = requests.get(url, params=params)
        data = res.json()

        if "claims" not in data:
            return None

        results = []
        for claim in data["claims"][:3]:
            text = claim.get("text", "")
            for review in claim.get("claimReview", []):
                results.append({
                    "claim": text,
                    "rating": review.get("textualRating"),
                    "publisher": review.get("publisher", {}).get("name"),
                    "url": review.get("url")
                })

        return results

    except Exception as e:
        return None